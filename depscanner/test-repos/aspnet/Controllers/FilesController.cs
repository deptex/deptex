using System.IO;
using Microsoft.AspNetCore.Mvc;

namespace Deptex.Dogfood.AspNet.Controllers;

[ApiController]
[Route("files")]
public class FilesController : ControllerBase
{
    [HttpGet("read")]
    public IActionResult Read([FromQuery] string path)
    {
        // REACHABLE: path_traversal — query path flows unchecked into File.ReadAllText.
        var target = path;
        var content = File.ReadAllText(target);
        return Ok(content.Length);
    }

    [HttpGet("open/{name}")]
    public IActionResult Open([FromRoute] string name)
    {
        // REACHABLE: path_traversal — route segment flows unchecked into a StreamReader.
        var file = name;
        using var reader = new StreamReader(file);
        return Ok(reader.Peek());
    }
}
