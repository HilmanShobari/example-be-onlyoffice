const express = require('express');
const multer = require('multer');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const axios = require('axios');

const app = express();
const PORT = 3001;
const ONLYOFFICE_JWT_SECRET = 'secret';

// Rate limiting cache for file requests
const requestCache = new Map();
const RATE_LIMIT_WINDOW = 1000; // 1 second
const MAX_REQUESTS_PER_WINDOW = 5;

// File monitoring storage
const fileMonitors = new Map(); // fileId -> { timeout, lastModified, isMonitoring }
let versionCounter = 1;

// CORS configuration
const corsOptions = {
    origin: ['http://localhost:3000', 'http://localhost:8888'],
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    credentials: true,
    optionsSuccessStatus: 200
};

// Middleware
app.use(cors(corsOptions));
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// Request logging
app.use((req, res, next) => {
    console.log(`${new Date().toISOString()} - ${req.method} ${req.path}`);
    next();
});

// Rate limiting middleware for specific endpoints
const rateLimit = (req, res, next) => {
    const key = `${req.ip}_${req.path}_${req.params.id || ''}`;
    const now = Date.now();
    
    if (!requestCache.has(key)) {
        requestCache.set(key, { count: 1, firstRequest: now });
        next();
        return;
    }
    
    const requestData = requestCache.get(key);
    
    // Reset counter if window has passed
    if (now - requestData.firstRequest > RATE_LIMIT_WINDOW) {
        requestCache.set(key, { count: 1, firstRequest: now });
        next();
        return;
    }
    
    // Check if exceeded limit
    if (requestData.count >= MAX_REQUESTS_PER_WINDOW) {
        console.warn(`Rate limit exceeded for ${key}`);
        return res.status(429).json({ 
            error: 'Too many requests', 
            retryAfter: RATE_LIMIT_WINDOW 
        });
    }
    
    // Increment counter
    requestData.count++;
    next();
};

// Create uploads directory if it doesn't exist
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) {
    fs.mkdirSync(uploadsDir, { recursive: true });
}

// Static files
app.use('/uploads', express.static(uploadsDir));

// Configure multer for file uploads
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, uploadsDir);
    },
    filename: (req, file, cb) => {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname));
    }
});

const upload = multer({ 
    storage: storage,
    limits: {
        fileSize: 50 * 1024 * 1024 // 50MB limit
    },
    fileFilter: (req, file, cb) => {
        // Accept common document formats
        const allowedTypes = ['.docx', '.xlsx', '.pptx', '.doc', '.xls', '.ppt', '.pdf', '.txt'];
        const fileExt = path.extname(file.originalname).toLowerCase();
        if (allowedTypes.includes(fileExt)) {
            cb(null, true);
        } else {
            cb(new Error('File type not supported'), false);
        }
    }
});

// OnlyOffice Document Server URL (dari Docker container Anda)
const DOCUMENT_SERVER_URL = 'http://localhost:8888';

// File config cache to avoid repeated processing
const configCache = new Map();
const CONFIG_CACHE_TTL = 60000; // 1 minute

// Generate JWT token for OnlyOffice (optional, untuk keamanan)
function generateJWT(payload) {
    const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
    const payloadBase64 = Buffer.from(JSON.stringify(payload)).toString('base64url');
    const signature = crypto
        .createHmac('sha256', ONLYOFFICE_JWT_SECRET)
        .update(`${header}.${payloadBase64}`)
        .digest('base64url');
    
    return `${header}.${payloadBase64}.${signature}`;
}

// Upload file
app.post('/api/upload', upload.single('document'), (req, res) => {
    if (!req.file) {
        return res.status(400).json({ error: 'No file uploaded' });
    }

    const fileInfo = {
        id: req.file.filename,
        name: req.file.originalname,
        size: req.file.size,
        path: req.file.path,
        url: `http://localhost:${PORT}/uploads/${req.file.filename}`,
        uploadDate: new Date().toISOString()
    };

    console.log('File uploaded:', fileInfo);

    res.json({
        success: true,
        message: 'File uploaded successfully',
        file: fileInfo
    });
});

// Get file info for OnlyOffice with rate limiting and caching
app.get('/api/file/:id', rateLimit, (req, res) => {
    const fileId = req.params.id;
    const filePath = path.join(uploadsDir, fileId);
    
    // Check cache first
    const cacheKey = fileId;
    if (configCache.has(cacheKey)) {
        const cached = configCache.get(cacheKey);
        if (Date.now() - cached.timestamp < CONFIG_CACHE_TTL) {
            console.log('Returning cached config for:', fileId);
            return res.json(cached.data);
        } else {
            configCache.delete(cacheKey);
        }
    }
    
    console.log('Getting file info for:', fileId);
    
    if (!fs.existsSync(filePath)) {
        return res.status(404).json({ error: 'File not found' });
    }

    const stats = fs.statSync(filePath);
    const fileUrl = `http://host.docker.internal:${PORT}/uploads/${fileId}`;
    
    // Generate unique key for OnlyOffice
    const documentKey = crypto.createHash('md5').update(fileId + stats.mtime.getTime()).digest('hex');
    console.log('file type:', path.extname(fileId).substring(1));
    console.log('documentKey: ', documentKey);
    
    // OnlyOffice configuration
    const config = {
        document: {
            fileType: path.extname(fileId).substring(1),
            key: documentKey,
            title: fileId,
            url: fileUrl
        },
        documentType: getDocumentType(path.extname(fileId)),
        editorConfig: {
            mode: 'edit', // 'edit' atau 'view'
            lang: 'id',
            callbackUrl: `http://host.docker.internal:${PORT}/api/callback/${fileId}`,
            user: {
                id: 'user-1',
                name: 'User'
            }
        },
        height: '100%',
        width: '100%',
    };
    
    config.token = generateJWT(config)

    const responseData = {
        success: true,
        config: config,
        documentServerUrl: DOCUMENT_SERVER_URL
    };

    console.log('responseData: ', responseData);

    // Cache the response
    configCache.set(cacheKey, {
        data: responseData,
        timestamp: Date.now()
    });

    console.log('Generated new config for:', fileId);
    res.json(responseData);
});

// OnlyOffice callback untuk menyimpan perubahan
app.post('/api/callback/:id', (req, res) => {
    const fileId = req.params.id;
    const body = req.body;
    
    console.log('OnlyOffice callback received:', {
        fileId,
        status: body.status,
        body: body
    });
    
    if (body.status === 2) { // Document ready for saving
        const downloadUrl = body.url;
        const filePath = path.join(uploadsDir, fileId);
        
        console.log('Saving document from:', downloadUrl, 'to:', filePath);
        
        // Download file dari OnlyOffice dan simpan
        const https = require('https');
        const http = require('http');
        const client = downloadUrl.startsWith('https') ? https : http;
        
        const file = fs.createWriteStream(filePath);
        client.get(downloadUrl, (response) => {
            response.pipe(file);
            file.on('finish', () => {
                file.close();
                console.log(`File ${fileId} saved successfully`);
                // Invalidate cache when file is updated
                configCache.delete(fileId);
            });
        }).on('error', (err) => {
            console.error('Error downloading file:', err);
        });
    }
    
    res.json({ error: 0 });
});

// List all uploaded files
app.get('/api/files', (req, res) => {
    try {
        if (!fs.existsSync(uploadsDir)) {
            return res.json({ success: true, files: [] });
        }

        const files = fs.readdirSync(uploadsDir).map(filename => {
            const filePath = path.join(uploadsDir, filename);
            const stats = fs.statSync(filePath);
            
            return {
                id: filename,
                name: filename,
                size: stats.size,
                url: `http://localhost:${PORT}/uploads/${filename}`,
                uploadDate: stats.birthtime.toISOString()
            };
        });
        
        console.log('Files list requested, found:', files.length, 'files');
        res.json({ success: true, files });
    } catch (error) {
        console.error('Error listing files:', error);
        res.status(500).json({ error: 'Failed to list files' });
    }
});

// Delete file
app.delete('/api/file/:id', (req, res) => {
    const fileId = req.params.id;
    const filePath = path.join(uploadsDir, fileId);
    
    console.log('Deleting file:', fileId);
    
    // Stop monitoring before deleting
    stopFileMonitoring(fileId);
    
    if (fs.existsSync(filePath)) {
        fs.unlinkSync(filePath);
        // Clear cache when file is deleted
        configCache.delete(fileId);
        console.log('File deleted successfully:', fileId);
        res.json({ success: true, message: 'File deleted successfully' });
    } else {
        res.status(404).json({ error: 'File not found' });
    }
});

// Save changes API endpoint
app.post('/api/save-changes', async (req, res) => {
    const { fileId, fileName, documentKey } = req.body;
    
    console.log('Save changes request received:', { fileId, fileName, documentKey });
    
    if (!fileId) {
        return res.status(400).json({ error: 'File ID is required' });
    }
    
    const filePath = path.join(uploadsDir, fileId);
    
    if (!fs.existsSync(filePath)) {
        return res.status(404).json({ error: 'File not found' });
    }
    
    try {
        // Start monitoring this file for changes
        startFileMonitoring(fileId, filePath);
        
        // Return success immediately
        res.json({ 
            success: true, 
            message: 'Save changes initiated successfully',
            fileId: fileId
        });
        
        console.log('Save changes response sent, monitoring started for:', fileId);
    } catch (error) {
        console.error('Error initiating save changes:', error);
        res.status(500).json({ error: 'Failed to initiate save changes' });
    }
});

// Function to start monitoring file changes
function startFileMonitoring(fileId, filePath) {
    // Stop existing monitoring if any
    if (fileMonitors.has(fileId)) {
        const monitor = fileMonitors.get(fileId);
        if (monitor.timeout) {
            clearTimeout(monitor.timeout);
        }
    }
    
    const stats = fs.statSync(filePath);
    const monitor = {
        timeout: null,
        lastModified: stats.mtime.getTime(),
        isMonitoring: true,
        filePath: filePath
    };
    
    fileMonitors.set(fileId, monitor);
    
    console.log(`Started monitoring file: ${fileId}`);
    
    // Start the monitoring loop
    monitorFileChanges(fileId);
}

// Function to monitor file changes every 0.5 seconds
function monitorFileChanges(fileId) {
    const monitor = fileMonitors.get(fileId);
    if (!monitor || !monitor.isMonitoring) {
        return;
    }
    
    try {
        if (!fs.existsSync(monitor.filePath)) {
            console.log(`File ${fileId} no longer exists, stopping monitoring`);
            fileMonitors.delete(fileId);
            return;
        }
        
        const stats = fs.statSync(monitor.filePath);
        const currentModified = stats.mtime.getTime();
        
        if (currentModified > monitor.lastModified) {
            console.log(`File ${fileId} has been modified, processing...`);
            
            // Update last modified time
            monitor.lastModified = currentModified;
            
            // Create versioning and convert to PDF
            processFileChanges(fileId, monitor.filePath);
        }
        
        // Schedule next check in 0.5 seconds
        monitor.timeout = setTimeout(() => {
            monitorFileChanges(fileId);
        }, 500);
        
    } catch (error) {
        console.error(`Error monitoring file ${fileId}:`, error);
        fileMonitors.delete(fileId);
    }
}

// Function to process file changes (versioning + PDF conversion)
async function processFileChanges(fileId, filePath) {
    try {
        console.log(`Processing changes for file: ${fileId}`);
        
        // Create version backup
        await createFileVersion(fileId, filePath);
        
        // Convert to PDF using OnlyOffice
        await convertToPDF(fileId, filePath);
        
        console.log(`Successfully processed changes for file: ${fileId}`);
        
    } catch (error) {
        console.error(`Error processing file changes for ${fileId}:`, error);
    }
}

// Function to create file version backup
async function createFileVersion(fileId, filePath) {
    try {
        const fileExt = path.extname(fileId);
        const fileNameWithoutExt = path.basename(fileId, fileExt);
        const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
        const versionFileName = `${fileNameWithoutExt}_v${versionCounter++}_${timestamp}${fileExt}`;
        const versionPath = path.join(uploadsDir, versionFileName);
        
        // Copy current file to version backup
        fs.copyFileSync(filePath, versionPath);
        
        console.log(`Created version backup: ${versionFileName}`);
        
    } catch (error) {
        console.error('Error creating file version:', error);
        throw error;
    }
}

// Function to convert document to PDF using OnlyOffice
async function convertToPDF(fileId, filePath) {
    try {
        const fileExt = path.extname(fileId).toLowerCase();
        
        // Only convert document types that OnlyOffice can handle
        if (!['.docx', '.doc', '.xlsx', '.xls', '.pptx', '.ppt'].includes(fileExt)) {
            console.log(`Skipping PDF conversion for file type: ${fileExt}`);
            return;
        }
        
        const fileUrl = `http://host.docker.internal:${PORT}/uploads/${fileId}`;
        const outputFileName = path.basename(fileId, fileExt) + '.pdf';
        const outputPath = path.join(uploadsDir, outputFileName);
        
        // OnlyOffice Document Server conversion API
        const conversionRequest = {
            async: false,
            filetype: fileExt.substring(1), // Remove the dot
            key: crypto.createHash('md5').update(fileId + Date.now()).digest('hex'),
            outputtype: 'pdf',
            title: fileId,
            url: fileUrl
        };
        
        // Add JWT token if needed
        const token = generateJWT(conversionRequest);
        
        console.log('Starting PDF conversion for:', fileId);
        
        const response = await axios.post(`http://localhost:8888/ConvertService.ashx`, conversionRequest, {
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`
            },
            timeout: 30000
        });
        
        if (response.data && response.data.endConvert && response.data.fileUrl) {
            // Download the converted PDF
            const pdfResponse = await axios.get(response.data.fileUrl, {
                responseType: 'stream',
                timeout: 30000
            });
            
            const writeStream = fs.createWriteStream(outputPath);
            pdfResponse.data.pipe(writeStream);
            
            await new Promise((resolve, reject) => {
                writeStream.on('finish', resolve);
                writeStream.on('error', reject);
            });
            
            console.log(`PDF conversion completed: ${outputFileName}`);
            
        } else {
            console.error('PDF conversion failed:', response.data);
        }
        
    } catch (error) {
        console.error('Error converting to PDF:', error);
        // Don't throw error to avoid stopping the monitoring process
    }
}

// Function to stop monitoring a file
function stopFileMonitoring(fileId) {
    const monitor = fileMonitors.get(fileId);
    if (monitor) {
        monitor.isMonitoring = false;
        if (monitor.timeout) {
            clearTimeout(monitor.timeout);
        }
        fileMonitors.delete(fileId);
        console.log(`Stopped monitoring file: ${fileId}`);
    }
}

// Helper function to determine document type for OnlyOffice
function getDocumentType(extension) {
    const ext = extension.toLowerCase();
    
    if (['.doc', '.docx', '.txt', '.rtf', '.odt'].includes(ext)) {
        return 'text';
    } else if (['.xls', '.xlsx', '.ods', '.csv'].includes(ext)) {
        return 'spreadsheet';
    } else if (['.ppt', '.pptx', '.odp'].includes(ext)) {
        return 'presentation';
    } else {
        return 'text'; // default
    }
}

// Clean up old cache entries periodically
setInterval(() => {
    const now = Date.now();
    for (const [key, value] of configCache.entries()) {
        if (now - value.timestamp > CONFIG_CACHE_TTL) {
            configCache.delete(key);
        }
    }
    
    // Clean up rate limiting cache
    for (const [key, value] of requestCache.entries()) {
        if (now - value.firstRequest > RATE_LIMIT_WINDOW * 2) {
            requestCache.delete(key);
        }
    }
    
    // Clean up file monitors that have been inactive for more than 10 minutes
    for (const [fileId, monitor] of fileMonitors.entries()) {
        if (monitor.lastModified && (now - monitor.lastModified > 10 * 60 * 1000)) {
            console.log(`Cleaning up inactive monitor for file: ${fileId}`);
            stopFileMonitoring(fileId);
        }
    }
}, 60000); // Clean every minute

// API to stop monitoring a specific file
app.post('/api/stop-monitoring/:id', (req, res) => {
    const fileId = req.params.id;
    
    console.log('Stop monitoring request for:', fileId);
    
    if (fileMonitors.has(fileId)) {
        stopFileMonitoring(fileId);
        res.json({ success: true, message: `Monitoring stopped for file: ${fileId}` });
    } else {
        res.json({ success: true, message: `No active monitoring found for file: ${fileId}` });
    }
});

// API to get monitoring status
app.get('/api/monitoring-status', (req, res) => {
    const monitoringStatus = [];
    
    for (const [fileId, monitor] of fileMonitors.entries()) {
        monitoringStatus.push({
            fileId: fileId,
            isMonitoring: monitor.isMonitoring,
            lastModified: new Date(monitor.lastModified).toISOString(),
            filePath: monitor.filePath
        });
    }
    
    res.json({
        success: true,
        activeMonitors: monitoringStatus.length,
        monitors: monitoringStatus
    });
});

// API to get file versions
app.get('/api/file-versions/:id', (req, res) => {
    const fileId = req.params.id;
    const fileExt = path.extname(fileId);
    const fileNameWithoutExt = path.basename(fileId, fileExt);
    
    try {
        if (!fs.existsSync(uploadsDir)) {
            return res.json({ success: true, versions: [] });
        }

        const versions = fs.readdirSync(uploadsDir)
            .filter(filename => {
                return filename.startsWith(fileNameWithoutExt + '_v') && filename.endsWith(fileExt);
            })
            .map(filename => {
                const filePath = path.join(uploadsDir, filename);
                const stats = fs.statSync(filePath);
                
                return {
                    filename: filename,
                    size: stats.size,
                    url: `http://localhost:${PORT}/uploads/${filename}`,
                    createdDate: stats.birthtime.toISOString(),
                    modifiedDate: stats.mtime.toISOString()
                };
            })
            .sort((a, b) => new Date(b.createdDate) - new Date(a.createdDate));
        
        console.log(`Found ${versions.length} versions for file: ${fileId}`);
        res.json({ success: true, versions });
    } catch (error) {
        console.error('Error getting file versions:', error);
        res.status(500).json({ error: 'Failed to get file versions' });
    }
});

// Error handling middleware
app.use((err, req, res, next) => {
    console.error('Server error:', err);
    res.status(500).json({ 
        error: 'Internal server error',
        message: err.message 
    });
});

// 404 handler
app.use((req, res) => {
    res.status(404).json({ error: 'Endpoint not found' });
});

app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
    console.log(`OnlyOffice Document Server URL: ${DOCUMENT_SERVER_URL}`);
    console.log(`Uploads directory: ${uploadsDir}`);
}); 