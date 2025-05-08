# Secure File Upload Service (.NET 8 + Background Processing)

This project provides a secure and efficient file upload service using ASP.NET Core and Background Services.

## Features

- ✅ Secure file upload via HTTP POST
- 🧪 Simulated antivirus scan with delay (configurable)
- 🔍 File content-type validation (PDF, JPEG, DOCX, TXT)
- 📁 Asynchronous background processing using `Channel<T>`
- 📊 Upload status tracking (`/api/fileupload/status/{id}`)

## Tech Stack

- ASP.NET Core 8 Web API
- BackgroundService & Channel for async processing
- In-memory status tracking with ConcurrentDictionary
- Configurable via `appsettings.json`

## API Endpoints

### POST `/api/fileupload`
Upload a file.

**Form Data Parameters:**
- `file`: The file to upload
- `simulateScan`: (bool) Whether to simulate antivirus scan

**Response:**
```
{
  "processingId": "123e4567-e89b-12d3-a456-426614174000"
}
```

### GET `/api/fileupload/status/{id}`
Get the processing status of a file.

**Possible Values:** `Queued`, `Scanning`, `Processing`, `Completed`, `VirusDetected`, `Failed`
