const express = require('express');
const multer = require('multer');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

const app = express();
const PORT = 3001;
const ONLYOFFICE_JWT_SECRET = 'secret';

// Rate limiting cache for file requests
const requestCache = new Map();
const RATE_LIMIT_WINDOW = 1000; // 1 second
const MAX_REQUESTS_PER_WINDOW = 5;

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
}, 60000); // Clean every minute

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