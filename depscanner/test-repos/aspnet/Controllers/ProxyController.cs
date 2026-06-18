using System.Net.Http;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;

namespace Deptex.Dogfood.AspNet.Controllers;

[ApiController]
[Route("proxy")]
public class ProxyController : ControllerBase
{
    private readonly HttpClient _http = new HttpClient();

    [HttpGet("fetch")]
    public async Task<IActionResult> Fetch([FromQuery] string url)
    {
        // REACHABLE: ssrf — query URL flows unchecked into HttpClient.GetAsync.
        var target = url;
        var resp = await _http.GetAsync(target);
        return Ok((int)resp.StatusCode);
    }

    [HttpGet("go")]
    public IActionResult Go([FromQuery] string next)
    {
        // REACHABLE: open_redirect — query value flows unchecked into Redirect.
        var dest = next;
        return Redirect(dest);
    }
}
