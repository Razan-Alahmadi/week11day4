using Microsoft.AspNetCore.Mvc;
using System.IO;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Configuration;
using System.Threading.Channels;
using Microsoft.AspNetCore.RateLimiting;
using System.Net.Mime;

[ApiController]
[Route("api/[controller]")]
public class UploadController : ControllerBase
{
    private readonly ILogger<UploadController> _logger;
    private readonly IConfiguration _config;
    private readonly Channel<FileUploadTask> _channel;

    private readonly long _maxFileSize = 5 * 1024 * 1024;
    private static readonly string[] _prohibitedExtensions = [".exe", ".dll", ".bat", ".sh", ".js"];

    public UploadController(
        ILogger<UploadController> logger,
        IConfiguration config,
        Channel<FileUploadTask> channel)
    {
        _logger = logger;
        _config = config;
        _channel = channel;
    }

    [HttpPost]
    [EnableRateLimiting("UploadPolicy")]
    public async Task<IActionResult> Upload([FromForm] IFormFile file)
    {
        if (file == null || file.Length == 0)
            return BadRequest("No file uploaded.");

        if (file.Length > _maxFileSize)
            return BadRequest($"File size exceeds the maximum limit of {_maxFileSize / (1024 * 1024)} MB.");

        var extension = Path.GetExtension(file.FileName).ToLowerInvariant();
        if (_prohibitedExtensions.Contains(extension))
            return BadRequest("Executable files are not allowed.");

        var sanitizedFileName = SanitizeFileName(file.FileName);

        byte[] fileContent;
        using (var ms = new MemoryStream())
        {
            await file.CopyToAsync(ms);
            fileContent = ms.ToArray();
        }

        var processingId = Guid.NewGuid().ToString();
        UploadStatusTracker.StatusMap[processingId] = "Queued";

        var task = new FileUploadTask
        {
            ProcessingId = processingId,
            FileContent = fileContent,
            OriginalFileName = sanitizedFileName,
            SimulateScan = _config.GetValue<bool>("SimulateAntivirusScan"),
            ScanDelayMs = _config.GetValue<int>("ScanDelayMilliseconds"),
            StoragePath = Path.Combine("uploads", sanitizedFileName)
        };

        await _channel.Writer.WriteAsync(task);

        return Accepted(new { ProcessingId = processingId, Message = "File queued for processing." });
    }

    [HttpGet("status/{id}")]
    public IActionResult GetStatus(string id)
    {
        if (UploadStatusTracker.StatusMap.TryGetValue(id, out var status))
        {
            return Ok(new { ProcessingId = id, Status = status });
        }
        return NotFound("Processing ID not found.");
    }

    // Helper: Sanitize file names
    private string SanitizeFileName(string fileName)
    {
        fileName = Path.GetFileName(fileName); // Prevent directory traversal
        return Regex.Replace(fileName, @"[^a-zA-Z0-9_\.\-]", "_");
    }
}
