using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;

namespace Example.Controllers;

[ApiController]
[Route("ops")]
public class OpsController : ControllerBase
{
    [HttpGet("ping")]
    public IActionResult Ping([FromQuery] string id)
    {
        // SAFE: coerce to int — int.Parse is a sanitizer for command_injection.
        var safeId = int.Parse(id);
        var p = Process.Start("cmd.exe", "/c ping host-" + safeId);
        if (p != null)
        {
            p.WaitForExit();
        }
        return Ok();
    }
}
