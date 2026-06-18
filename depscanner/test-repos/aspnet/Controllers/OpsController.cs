using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;

namespace Deptex.Dogfood.AspNet.Controllers;

[ApiController]
[Route("ops")]
public class OpsController : ControllerBase
{
    [HttpGet("ping")]
    public IActionResult Ping([FromQuery] string host)
    {
        // REACHABLE: command_injection — host concatenated into a shell argument.
        var target = host;
        Process.Start("sh", "-c ping -c1 " + target);
        return Ok();
    }

    [HttpGet("trace")]
    public IActionResult Trace([FromHeader(Name = "X-Target")] string target)
    {
        // REACHABLE: command_injection — request header concatenated into a shell argument.
        var dest = target;
        Process.Start("sh", "-c traceroute " + dest);
        return Ok();
    }
}
