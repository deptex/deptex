# minimal-apis / reachable — CVE-2024-21319 (JWT validation bypass)

- **Vulnerable dep:** `Microsoft.IdentityModel.JsonWebTokens@6.27.0`
- **Sink:** `Program.cs:13` — `JsonWebTokenHandler.ValidateToken(raw, ...)` on user-supplied JWT.
- **Entry point:** `app.MapPost("/token", ...)` — minimal API endpoint.
- **Expected verdict:** `data_flow`.
