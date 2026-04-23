import { csharpModule } from '../../tree-sitter-extractor/languages/csharp';
import { dep, entryPointsFor, extractInline } from '../test-helpers';

describe('C# framework detectors', () => {
  describe('aspnet-core', () => {
    it('detects [ApiController] + [HttpGet]/[HttpPost]', async () => {
      const file = await extractInline(
        csharpModule,
        `
using Microsoft.AspNetCore.Mvc;

namespace MyApp.Controllers;

[ApiController]
[Route("api/[controller]")]
public class UsersController : ControllerBase
{
    [HttpGet("{id}")]
    public IActionResult GetUser(int id) => Ok();

    [HttpPost]
    public IActionResult Create([FromBody] User user) => Created("", user);
}
`,
        '/project/Controllers/UsersController.cs',
        [dep('Microsoft.AspNetCore.Mvc.Core', 'Microsoft.AspNetCore.Mvc')],
      );
      const eps = entryPointsFor(file, 'aspnet-core');
      expect(eps.length).toBeGreaterThanOrEqual(2);
      const byMethod = new Map(eps.map((e) => [e.httpMethod, e.routePattern]));
      expect(byMethod.has('GET')).toBe(true);
      expect(byMethod.has('POST')).toBe(true);
    });
  });

  describe('minimal-apis', () => {
    it('detects app.MapGet / app.MapPost', async () => {
      const file = await extractInline(
        csharpModule,
        `
var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();

app.MapGet("/", () => "Hello World!");
app.MapPost("/items", (Item item) => Results.Created("/items/1", item));
app.MapDelete("/items/{id}", (int id) => Results.NoContent());

app.Run();
`,
        '/project/Program.cs',
        [],
      );
      const eps = entryPointsFor(file, 'minimal-apis');
      expect(eps.length).toBeGreaterThanOrEqual(3);
      const byMethod = new Map(eps.map((e) => [e.httpMethod, e.routePattern]));
      expect(byMethod.get('GET')).toBe('/');
      expect(byMethod.get('POST')).toBe('/items');
      expect(byMethod.get('DELETE')).toBe('/items/{id}');
    });
  });
});
