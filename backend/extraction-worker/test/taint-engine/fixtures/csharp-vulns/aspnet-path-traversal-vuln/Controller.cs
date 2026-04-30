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
        var bytes = _service.Read(name);
        return File(bytes, "application/octet-stream");
    }
}
