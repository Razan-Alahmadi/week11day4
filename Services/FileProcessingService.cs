using System.Threading.Channels;
using System.Collections.Concurrent;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Configuration;

public class FileProcessingService : BackgroundService
{
    private readonly Channel<FileUploadTask> _uploadChannel;
    private readonly ILogger<FileProcessingService> _logger;
    private readonly IConfiguration _config;

    public FileProcessingService(
        Channel<FileUploadTask> uploadChannel,
        ILogger<FileProcessingService> logger,
        IConfiguration config)
    {
        _uploadChannel = uploadChannel;
        _logger = logger;
        _config = config;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        await foreach (var task in _uploadChannel.Reader.ReadAllAsync(stoppingToken))
        {
            try
            {
                _logger.LogInformation("Processing file: {FileName}", task.OriginalFileName);
                UploadStatusTracker.StatusMap[task.ProcessingId] = "Scanning";

                // Simulate antivirus scan delay
                if (task.SimulateScan)
                {
                    var delay = task.ScanDelayMs > 0 ? task.ScanDelayMs : _config.GetValue<int>("ScanDelayMilliseconds", 1000);
                    await Task.Delay(delay, stoppingToken);
                }

                // Check file header ("magic bytes")
                if (!IsFileHeaderValid(task.FileContent))
                {
                    UploadStatusTracker.StatusMap[task.ProcessingId] = "VirusDetected";
                    _logger.LogWarning("File {FileName} failed header validation", task.OriginalFileName);
                    continue;
                }

                UploadStatusTracker.StatusMap[task.ProcessingId] = "Processing";

                // Ensure the upload directory exists
                var directory = Path.GetDirectoryName(task.StoragePath)!;
                if (!Directory.Exists(directory))
                {
                    Directory.CreateDirectory(directory);
                }

                // Write file to disk
                await File.WriteAllBytesAsync(task.StoragePath, task.FileContent, stoppingToken);

                UploadStatusTracker.StatusMap[task.ProcessingId] = "Completed";
                _logger.LogInformation("File {FileName} saved successfully", task.OriginalFileName);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to process file {FileName}", task.OriginalFileName);
                UploadStatusTracker.StatusMap[task.ProcessingId] = "Failed";
            }
        }
    }

    private bool IsFileHeaderValid(byte[] content)
    {
        if (content.Length >= 4)
        {
            // PDF: 0x25 0x50 0x44 0x46 (%PDF)
            if (content[0] == 0x25 && content[1] == 0x50 && content[2] == 0x44 && content[3] == 0x46)
                return true;

            // JPEG: 0xFF 0xD8 0xFF
            if (content[0] == 0xFF && content[1] == 0xD8 && content[2] == 0xFF)
                return true;

            // DOCX/ZIP: 0x50 0x4B 0x03 0x04
            if (content[0] == 0x50 && content[1] == 0x4B && content[2] == 0x03 && content[3] == 0x04)
                return true;

            // TXT (heuristic: basic ASCII)
            if (content.Take(20).All(b => b == 0x09 || b == 0x0A || b == 0x0D || (b >= 0x20 && b <= 0x7E)))
                return true;
        }

        return false;
    }
}
