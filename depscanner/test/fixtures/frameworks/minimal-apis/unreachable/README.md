# minimal-apis / unreachable — CVE-2024-21319

- **Vulnerable dep:** `Microsoft.IdentityModel.JsonWebTokens@6.27.0` (declared, not imported).
- **Why unreachable:** zero `Map*` endpoints; no `JsonWebTokenHandler.ValidateToken` call.
- **Expected verdict:** `module`.
