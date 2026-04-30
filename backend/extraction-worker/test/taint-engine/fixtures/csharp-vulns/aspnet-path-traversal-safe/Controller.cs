using System.IO;

using Microsoft.AspNetCore.Mvc;

namespace Example.Controllers;

[ApiController]
[Route("files")]
public class FileController : ControllerBase
{
    private readonly FileService _service;

    public FileController(FileService service)
    {
        _service = service;
    }

    [HttpGet("download")]
    public IActionResult Download([FromQuery] string name)
    {
        // Strip directory components — only the filename reaches the service.
        var safe = Path.GetFileName(name);
        var bytes = _service.Read(safe);
        return File(bytes, "application/octet-stream");
    }
}
