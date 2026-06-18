using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;

namespace Deptex.Dogfood.AspNet.Controllers;

[ApiController]
[Route("content")]
public class ContentController : ControllerBase
{
    private readonly ILogger<ContentController> _log;

    public ContentController(ILogger<ContentController> log)
    {
        _log = log;
    }

    [HttpGet("echo")]
    public async Task Echo([FromQuery] string message)
    {
        // REACHABLE: xss — query value written unencoded into the response body.
        var body = message;
        await Response.WriteAsync(body);
    }

    [HttpGet("match")]
    public IActionResult Match([FromQuery] string pattern)
    {
        // REACHABLE: redos — untrusted pattern compiled into a Regex.
        var pat = pattern;
        var rx = new Regex(pat);
        return Ok(rx.IsMatch("sample-input"));
    }

    [HttpGet("audit")]
    public IActionResult Audit([FromHeader(Name = "User-Agent")] string agent)
    {
        // REACHABLE: log_injection — request header written unencoded into a log line.
        var ua = agent;
        _log.LogInformation(ua);
        return Ok();
    }
}
