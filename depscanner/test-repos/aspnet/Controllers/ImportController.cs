using System.IO;
using System.Runtime.Serialization;
using System.Xml;
using Microsoft.AspNetCore.Mvc;

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
}
