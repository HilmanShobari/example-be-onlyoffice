# OnlyOffice Backend Server

Backend server untuk aplikasi OnlyOffice document editor.

## Instalasi

```bash
npm install
```

## Menjalankan Server

### Mode Development

```bash
npm run dev
```

### Mode Production

```bash
npm start
```

Server akan berjalan di `http://localhost:3001`

## Endpoints

- `GET /api/health` - Health check endpoint
- `GET /api/onlyoffice/healthcheck` - OnlyOffice server health check
- `POST /api/upload` - Upload dokumen
- `GET /api/files` - Daftar file yang diupload
- `GET /api/config/:id` - Konfigurasi OnlyOffice untuk dokumen

## Environment

Pastikan OnlyOffice Document Server berjalan di `http://localhost:8888`

## File Upload

File yang diupload akan disimpan di folder `uploads/` dengan format yang didukung:

- .docx, .doc
- .xlsx, .xls
- .pptx, .ppt
- .pdf
- .txt
