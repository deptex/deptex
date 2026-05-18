using System.Data.SqlClient;
using Microsoft.AspNetCore.Mvc;

namespace Deptex.Fixtures.AspNetSqli.Controllers;

[ApiController]
[Route("users")]
public class UsersController : ControllerBase
{
    private const string ConnString = "Server=db;Database=app;Trusted_Connection=True;";

    [HttpGet("by-name")]
    public IActionResult GetByName([FromQuery] string name)
    {
        // REACHABLE: query parameter concatenated into SqlCommand text.
        using var conn = new SqlConnection(ConnString);
        using var cmd = new SqlCommand($"SELECT * FROM users WHERE name = '{name}'", conn);
        conn.Open();
        using var reader = cmd.ExecuteReader();
        return Ok(reader.HasRows);
    }

    [HttpGet("{id:int}")]
    public IActionResult GetById(int id)
    {
        // UNREACHABLE: parameterised query.
        using var conn = new SqlConnection(ConnString);
        using var cmd = new SqlCommand("SELECT * FROM users WHERE id = @id", conn);
        cmd.Parameters.AddWithValue("@id", id);
        conn.Open();
        using var reader = cmd.ExecuteReader();
        return Ok(reader.HasRows);
    }
}
