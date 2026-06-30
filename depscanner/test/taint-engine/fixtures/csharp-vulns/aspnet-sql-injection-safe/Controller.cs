using System.Data.SqlClient;
using Microsoft.AspNetCore.Mvc;

namespace Example.Controllers;

[ApiController]
[Route("users")]
public class UserController : ControllerBase
{
    private readonly string _connectionString;
    private readonly IReportEngine _reportEngine;

    public UserController(string connectionString, IReportEngine reportEngine)
    {
        _connectionString = connectionString;
        _reportEngine = reportEngine;
    }

    [HttpGet("search")]
    public IActionResult Search([FromQuery] string q)
    {
        // SAFE: q is bound as a parameter via AddWithValue, not concatenated.
        using (var conn = new SqlConnection(_connectionString))
        {
            conn.Open();
            using (var cmd = new SqlCommand(
                "SELECT id, name FROM users WHERE name = @name", conn))
            {
                cmd.Parameters.AddWithValue("@name", q);
                var reader = cmd.ExecuteReader();
                return Ok(reader);
            }
        }
    }

    [HttpGet("report")]
    public IActionResult Report([FromQuery] string q)
    {
        // T2 FP-shape proof: `ExecuteReader` / `ExecuteNonQuery` are NOT SQL
        // sinks — they carry no query argument (the SQL enters via the
        // SqlCommand constructor / CommandText). The old `*.ExecuteReader(*)`
        // / `*.ExecuteNonQuery(*)` sinks (argument_indices: []) fired on ANY
        // receiver that received a tainted argument, so this benign call to an
        // unrelated report engine produced a sql_injection false positive.
        // After the sinks were removed, it must produce zero flows.
        var rows = _reportEngine.ExecuteReader(q);
        _reportEngine.ExecuteNonQuery(q);
        return Ok(rows);
    }
}

public interface IReportEngine
{
    object ExecuteReader(string name);
    void ExecuteNonQuery(string name);
}
