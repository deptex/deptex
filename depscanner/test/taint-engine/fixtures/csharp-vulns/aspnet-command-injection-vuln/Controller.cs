using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;

namespace Example.Controllers;

[ApiController]
[Route("ops")]
public class OpsController : ControllerBase
{
    [HttpGet("ping")]
    public IActionResult Ping([FromQuery] string host)
    {
        // VULNERABLE: host is interpolated unchecked into a shell argument.
        var p = Process.Start("cmd.exe", "/c ping " + host);
        if (p != null)
        {
            p.WaitForExit();
        }
        return Ok();
    }
}
