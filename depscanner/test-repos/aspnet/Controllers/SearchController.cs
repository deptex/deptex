using System.Data.SqlClient;
using Microsoft.AspNetCore.Mvc;

namespace Deptex.Dogfood.AspNet.Controllers;

[ApiController]
[Route("search")]
public class SearchController : ControllerBase
{
    private const string ConnString = "Server=db;Database=app;Trusted_Connection=True;";

    [HttpGet("products")]
    public IActionResult Products([FromQuery] string term)
    {
        // REACHABLE: sql_injection — query term concatenated into SQL text.
        var keyword = term;
        using var conn = new SqlConnection(ConnString);
        using var cmd = new SqlCommand(
            "SELECT id, name FROM products WHERE name LIKE '%" + keyword + "%'", conn);
        conn.Open();
        using var reader = cmd.ExecuteReader();
        return Ok(reader.HasRows);
    }

    [HttpGet("orders/{customer}")]
    public IActionResult Orders([FromRoute] string customer)
    {
        // REACHABLE: sql_injection — route segment concatenated into SQL text.
        var owner = customer;
        using var conn = new SqlConnection(ConnString);
        using var cmd = new SqlCommand(
            "SELECT * FROM orders WHERE customer = '" + owner + "'", conn);
        conn.Open();
        using var reader = cmd.ExecuteReader();
        return Ok(reader.HasRows);
    }
}
