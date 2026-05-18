using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

// CVE-2024-21319 — Microsoft.IdentityModel.JsonWebTokens 6.27.0 JWT
// validation bypass via crafted tokens.
var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();

app.MapPost("/token", (string raw) =>
{
    // Sink: validate user-supplied JWT with vulnerable validator.
    var handler = new JsonWebTokenHandler();
    var result = handler.ValidateToken(raw, new TokenValidationParameters());
    return result.IsValid ? "ok" : "invalid";
});

app.Run();
