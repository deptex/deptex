# aspnet

ASP.NET controller with one reachable SQL injection via `SqlCommand`
string interpolation. Stand-alone copy of upstream taint-engine fixture
`depscanner/fixtures/test-csharp-aspnet-sqli/` layered with dogfood
categories.

- **Ecosystem:** nuget
- **Framework:** ASP.NET Core
- **Reachable vuln dep:** `Microsoft.AspNetCore.Mvc.Core 2.2.5` +
  `System.Data.SqlClient 4.8.5` + `Newtonsoft.Json 13.0.1`.
- **Unreachable vuln dep:** `System.Text.RegularExpressions 4.3.0` —
  declared but never referenced from `Controllers/`.
- **Reachable handler:** `UsersController.cs:GetByName()`.
- **Unreachable handler:** `UsersController.cs:GetById()` —
  `AddWithValue` parameterised.

See `.deptex/SOURCE.md`.
