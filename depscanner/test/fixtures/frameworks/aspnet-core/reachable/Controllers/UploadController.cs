using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace Deptex.Fixture;

// CVE-2023-36038 — ASP.NET Core 7.0.10 DoS via Form parsing on hostile bodies.
[ApiController]
[Route("[controller]")]
public class UploadController : ControllerBase
{
    [HttpPost]
    public IActionResult Upload([FromForm] IFormCollection form)
    {
        // Sink: IFormCollection model binding triggers vulnerable parser.
        return Ok(form.Count);
    }
}
