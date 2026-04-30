using System.Data.SqlClient;
using Microsoft.AspNetCore.Mvc;

namespace Example.Controllers;

[ApiController]
[Route("users")]
public class UserController : ControllerBase
{
    private readonly string _connectionString;

    public UserController(string connectionString)
    {
        _connectionString = connectionString;
    }

    [HttpGet("search")]
    public IActionResult Search([FromQuery] string q)
    {
        // VULNERABLE: q is concatenated directly into the SQL string.
        using (var conn = new SqlConnection(_connectionString))
        {
            conn.Open();
            using (var cmd = new SqlCommand(
                "SELECT id, name FROM users WHERE name = '" + q + "'", conn))
            {
                var reader = cmd.ExecuteReader();
                return Ok(reader);
            }
        }
    }
}
