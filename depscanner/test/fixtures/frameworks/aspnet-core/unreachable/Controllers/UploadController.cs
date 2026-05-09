using Microsoft.AspNetCore.Mvc;

namespace Deptex.Fixture;

// Class declared but no [HttpPost]/[HttpGet] methods — no entry points;
// IFormCollection parser is unreachable.
[ApiController]
[Route("[controller]")]
public class UploadController : ControllerBase
{
    public string Unused() => "no route";
}
