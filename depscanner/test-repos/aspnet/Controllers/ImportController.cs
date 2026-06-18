using System.IO;
using System.Runtime.Serialization;
using System.Xml;
using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json;

namespace Deptex.Dogfood.AspNet.Controllers;

[ApiController]
[Route("import")]
public class ImportController : ControllerBase
{
    [HttpPost("profile")]
    public IActionResult Profile([FromBody] string payload)
    {
        // REACHABLE: deserialization — request body deserialized via DataContractSerializer.
        var data = payload;
        var serializer = new DataContractSerializer(typeof(object));
        using var stringReader = new StringReader(data);
        using var xmlReader = XmlReader.Create(stringReader);
        var obj = serializer.ReadObject(xmlReader);
        return Ok(obj != null);
    }

    [HttpPost("settings")]
    public IActionResult Settings([FromBody] string payload)
    {
        // REACHABLE: deserialization — user-supplied JSON payload deserialized
        // by Newtonsoft.Json with no MaxDepth cap (CVE-2024-21907, DoS).
        var json = payload;
        var settings = JsonConvert.DeserializeObject<object>(json);
        return Ok(settings != null);
    }
}
