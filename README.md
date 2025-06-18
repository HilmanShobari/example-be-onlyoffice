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

### File Management

- `POST /api/upload` - Upload dokumen
- `GET /api/files` - Daftar file yang diupload
- `DELETE /api/file/:id` - Hapus file

### OnlyOffice Integration

- `GET /api/file/:id` - Konfigurasi OnlyOffice untuk dokumen
- `POST /api/callback/:id` - Callback untuk menyimpan perubahan dari OnlyOffice

## Environment

Pastikan OnlyOffice Document Server berjalan di `http://localhost:8888`

## File Upload

File yang diupload akan disimpan di folder `uploads/` dengan format yang didukung:

- .docx, .doc
- .xlsx, .xls
- .pptx, .ppt
- .pdf
- .txt
