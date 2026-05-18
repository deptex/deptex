// Minimal API host with zero MapPost / MapGet endpoints; the JWT
// validation surface from Microsoft.IdentityModel.JsonWebTokens is
// never reached.
var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();
app.Run();
