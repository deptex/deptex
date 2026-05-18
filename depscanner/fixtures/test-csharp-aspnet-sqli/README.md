# test-csharp-aspnet-sqli

ASP.NET controller with one reachable SQL injection via
`SqlCommand(query, conn)` and string concatenation.

- **Ecosystem:** nuget
- **Framework:** ASP.NET Core
- **Vulnerable shape:** route query parameter concatenated into a
  `SqlCommand` text.
- **Reachable handler:** `UsersController.cs:GetByName()`.
- **Unreachable handler:** `UsersController.cs:GetById()` — uses
  `AddWithValue` parameterised query.

Expected snapshot: nuget deps in `deps.json`, taint-engine + semgrep
finding on `GetByName`.
