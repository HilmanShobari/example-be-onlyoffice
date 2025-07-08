require('dotenv').config();
const express = require('express');
const multer = require('multer');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const axios = require('axios');
const { v4: uuidv4 } = require('uuid');
const serverless = require('serverless-http');

const app = express();

// Configuration from environment variables
const PORT = process.env.PORT || 3001;
const ONLYOFFICE_URL = process.env.ONLYOFFICE_URL || 'http://192.168.30.91:8888';
const BACKEND_URL = process.env.BACKEND_URL || 'https://example-be-onlyoffice.vercel.app';
const ONLYOFFICE_JWT_SECRET = process.env.ONLYOFFICE_JWT_SECRET || 'dWNyZXJlaW5kbzI1';

console.log('🔧 Starting OnlyOffice Backend Server...');
console.log('🌐 Backend URL:', BACKEND_URL);
console.log('📄 OnlyOffice Server:', ONLYOFFICE_URL);
console.log('🔐 Using JWT Secret:', ONLYOFFICE_JWT_SECRET);
console.log('⚠️  Make sure JWT secret matches your OnlyOffice server!');

// Rate limiting cache for file requests
const requestCache = new Map();
const RATE_LIMIT_WINDOW = 1000; // 1 second
const MAX_REQUESTS_PER_WINDOW = 5;

// File monitoring storage
const fileMonitors = new Map(); // fileId -> { timeout, lastModified, isMonitoring }

// CORS configuration for Vercel
const corsOptions = {
    origin: '*',
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    credentials: true,
    optionsSuccessStatus: 200,
    allowedHeaders: ['Content-Type', 'Authorization', 'ngrok-skip-browser-warning']
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

// Create uploads directory if it doesn't exist (for local development)
const uploadsDir = process.env.VERCEL ? '/tmp/uploads' : path.join(__dirname, 'uploads');
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
        cb(null, uuidv4() + path.extname(file.originalname));
    }
});

const upload = multer({ 
    storage: storage,
    limits: {
        fileSize: 50 * 1024 * 1024 // 50MB limit
    },
    fileFilter: (req, file, cb) => {
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
const DOCUMENT_SERVER_URL = ONLYOFFICE_URL;

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

// Upload file with automatic PDF conversion
app.post('/api/upload', upload.single('document'), async (req, res) => {
    if (!req.file) {
        return res.status(400).json({ error: 'No file uploaded' });
    }

    const fileInfo = {
        id: req.file.filename,
        name: req.file.originalname,
        size: req.file.size,
        path: req.file.path,
        url: `${BACKEND_URL}/uploads/${req.file.filename}`,
        uploadDate: new Date().toISOString()
    };

    console.log('File uploaded:', fileInfo);

    // Check if file can be converted to PDF
    const fileExt = path.extname(req.file.filename).toLowerCase();
    const canConvertToPDF = ['.docx', '.doc', '.xlsx', '.xls', '.pptx', '.ppt'].includes(fileExt);
    
    let pdfInfo = null;
    
    if (canConvertToPDF) {
        try {
            console.log('Starting automatic PDF conversion for uploaded file:', req.file.filename);
            
            // Wait a moment to ensure file is fully written
            await new Promise(resolve => setTimeout(resolve, 500));
            
            const pdfFileName = await convertToPDF(req.file.filename, req.file.path);
            
            if (pdfFileName) {
                // Track the PDF relationship
                addFileRelationship(req.file.filename, pdfFileName, 'pdf');
                
                const pdfPath = path.join(uploadsDir, pdfFileName);
                const pdfStats = fs.statSync(pdfPath);
                
                pdfInfo = {
                    id: pdfFileName,
                    filename: pdfFileName,
                    size: pdfStats.size,
                    url: `${BACKEND_URL}/uploads/${pdfFileName}`,
                    createdDate: new Date().toISOString(),
                    type: 'pdf'
                };
                
                console.log('PDF conversion completed for upload:', pdfFileName);
            }
        } catch (error) {
            console.error('Error during automatic PDF conversion:', error);
            // Don't fail the upload if PDF conversion fails
        }
    }

    const response = {
        success: true,
        message: 'File uploaded successfully',
        file: fileInfo,
        pdf: pdfInfo,
        canConvertToPDF: canConvertToPDF
    };

    if (pdfInfo) {
        response.message += ' and converted to PDF';
    } else if (canConvertToPDF) {
        response.message += ' (PDF conversion failed)';
    }

    res.json(response);
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
    const fileUrl = `${BACKEND_URL}/uploads/${fileId}`;
    
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
            callbackUrl: `${BACKEND_URL}/api/callback/${fileId}`,
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
app.post('/api/callback/:id', async (req, res) => {
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
        
        try {
            // CREATE VERSION BACKUP BEFORE OVERWRITING
            if (fs.existsSync(filePath)) {
                console.log('Creating version backup before saving new version...');
                const versionFileName = await createFileVersionFromCallback(fileId, filePath);
                // Track the relationship
                addFileRelationship(fileId, versionFileName, 'version');
            }
            
            // Download file dari OnlyOffice dan simpan
            const https = require('https');
            const client = https;
            
            const file = fs.createWriteStream(filePath);
            client.get(downloadUrl, (response) => {
                response.pipe(file);
                file.on('finish', () => {
                    file.close();
                    console.log(`File ${fileId} saved successfully`);
                    // Invalidate cache when file is updated
                    configCache.delete(fileId);
                    
                    // Convert new version to PDF after saving
                    setTimeout(async () => {
                        try {
                            const pdfFileName = await convertToPDF(fileId, filePath);
                            if (pdfFileName) {
                                // Track the PDF relationship
                                addFileRelationship(fileId, pdfFileName, 'pdf');
                            }
                        } catch (err) {
                            console.error('PDF conversion error:', err);
                        }
                    }, 1000); // Wait 1 second to ensure file is fully written
                });
            }).on('error', (err) => {
                console.error('Error downloading file:', err);
            });
            
        } catch (error) {
            console.error('Error in callback processing:', error);
        }
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
                url: `${BACKEND_URL}/api/files/uploads/${filename}`,
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
        
        // Clean up file relationships
        if (fileRelationships.has(fileId)) {
            const relationship = fileRelationships.get(fileId);
            
            // Delete version files
            relationship.versions.forEach(versionInfo => {
                const versionPath = path.join(uploadsDir, versionInfo.id);
                if (fs.existsSync(versionPath)) {
                    fs.unlinkSync(versionPath);
                    console.log('Deleted version file:', versionInfo.id);
                }
            });
            
            // Delete PDF files
            relationship.pdfs.forEach(pdfInfo => {
                const pdfPath = path.join(uploadsDir, pdfInfo.id);
                if (fs.existsSync(pdfPath)) {
                    fs.unlinkSync(pdfPath);
                    console.log('Deleted PDF file:', pdfInfo.id);
                }
            });
            
            // Remove from relationships map
            fileRelationships.delete(fileId);
        }
        
        console.log('File and related versions/PDFs deleted successfully:', fileId);
        res.json({ success: true, message: 'File and related versions deleted successfully' });
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

// Function to process file changes (monitoring only - versioning handled in callback)
async function processFileChanges(fileId, filePath) {
    try {
        console.log(`Processing changes for file: ${fileId}`);
        
        // Note: Versioning is now handled in OnlyOffice callback
        // PDF conversion is also handled in callback to avoid duplication
        console.log(`File change detected for: ${fileId} - PDF conversion handled by callback`);
        
        console.log(`Successfully processed changes for file: ${fileId}`);
        
    } catch (error) {
        console.error(`Error processing file changes for ${fileId}:`, error);
    }
}

// Function to create file version backup
async function createFileVersion(fileId, filePath) {
    try {
        const fileExt = path.extname(fileId);
        const versionFileName = `${uuidv4()}${fileExt}`;
        const versionPath = path.join(uploadsDir, versionFileName);
        
        // Copy current file to version backup
        fs.copyFileSync(filePath, versionPath);
        
        console.log(`Created version backup: ${versionFileName}`);
        return versionFileName;
        
    } catch (error) {
        console.error('Error creating file version:', error);
        throw error;
    }
}

// Function to create file version backup specifically for callback
async function createFileVersionFromCallback(fileId, filePath) {
    try {
        const fileExt = path.extname(fileId);
        const versionFileName = `${uuidv4()}${fileExt}`;
        const versionPath = path.join(uploadsDir, versionFileName);
        
        // Copy current file to version backup
        fs.copyFileSync(filePath, versionPath);
        
        console.log(`Created callback version backup: ${versionFileName}`);
        return versionFileName;
        
    } catch (error) {
        console.error('Error creating callback file version:', error);
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
        
        const fileUrl = `${BACKEND_URL}/uploads/${fileId}`;
        // Generate unique PDF filename with UUID
        const outputFileName = `${uuidv4()}.pdf`;
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
        
        console.log('Starting PDF conversion for:', fileId, '-> PDF:', outputFileName);
        
        const response = await axios.post(`${ONLYOFFICE_URL}/ConvertService.ashx`, conversionRequest, {
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
            return outputFileName;
            
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

// Store file relationships for tracking versions and PDFs
const fileRelationships = new Map(); // originalFileId -> { versions: [], pdfs: [] }

// Helper function to add file relationship
function addFileRelationship(originalFileId, relatedFileId, type) {
    if (!fileRelationships.has(originalFileId)) {
        fileRelationships.set(originalFileId, { versions: [], pdfs: [] });
    }
    
    const relationship = fileRelationships.get(originalFileId);
    if (type === 'version') {
        relationship.versions.push({
            id: relatedFileId,
            createdAt: new Date().toISOString()
        });
    } else if (type === 'pdf') {
        relationship.pdfs.push({
            id: relatedFileId,
            createdAt: new Date().toISOString()
        });
    }
}

// API to get file versions using relationship tracking
app.get('/api/file-versions/:id', (req, res) => {
    const fileId = req.params.id;
    
    try {
        if (!fs.existsSync(uploadsDir)) {
            return res.json({ success: true, versions: [], pdfs: [] });
        }

        const relationship = fileRelationships.get(fileId) || { versions: [], pdfs: [] };
        
        // Get version files data
        const versions = relationship.versions
            .filter(versionInfo => {
                const filePath = path.join(uploadsDir, versionInfo.id);
                return fs.existsSync(filePath);
            })
            .map(versionInfo => {
                const filePath = path.join(uploadsDir, versionInfo.id);
                const stats = fs.statSync(filePath);
                
                return {
                    id: versionInfo.id,
                    filename: versionInfo.id,
                    size: stats.size,
                    url: `${BACKEND_URL}/uploads/${versionInfo.id}`,
                    createdDate: versionInfo.createdAt,
                    modifiedDate: stats.mtime.toISOString(),
                    type: 'version'
                };
            })
            .sort((a, b) => new Date(b.createdDate) - new Date(a.createdDate));
        
        // Get PDF files data
        const pdfs = relationship.pdfs
            .filter(pdfInfo => {
                const filePath = path.join(uploadsDir, pdfInfo.id);
                return fs.existsSync(filePath);
            })
            .map(pdfInfo => {
                const filePath = path.join(uploadsDir, pdfInfo.id);
                const stats = fs.statSync(filePath);
                
                return {
                    id: pdfInfo.id,
                    filename: pdfInfo.id,
                    size: stats.size,
                    url: `${BACKEND_URL}/uploads/${pdfInfo.id}`,
                    createdDate: pdfInfo.createdAt,
                    modifiedDate: stats.mtime.toISOString(),
                    type: 'pdf'
                };
            })
            .sort((a, b) => new Date(b.createdDate) - new Date(a.createdDate));
        
        console.log(`Found ${versions.length} versions and ${pdfs.length} PDFs for file: ${fileId}`);
        res.json({ 
            success: true, 
            originalFile: fileId,
            versions: versions,
            pdfs: pdfs,
            total: versions.length + pdfs.length
        });
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

// Start server for local development
if (!process.env.VERCEL) {
    app.listen(PORT, () => {
        console.log(`Server running on ${BACKEND_URL}`);
        console.log(`OnlyOffice Document Server URL: ${ONLYOFFICE_URL}`);
        console.log(`Uploads directory: ${uploadsDir}`);
    });
}

// Export for Vercel
module.exports = app;
module.exports.handler = serverless(app);