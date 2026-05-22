# SOURCE

Standalone copy of upstream taint-engine fixture:

- **Upstream path:** `depscanner/fixtures/test-csharp-aspnet-sqli/`
- **Upstream tree SHA at copy time:** `ee0b36a5ff202e4cd82570dbb418e4b944c911b0`
- **Files copied:** `Controllers/UsersController.cs` (namespace renamed
  `Deptex.Fixtures.AspNetSqli` → `Deptex.Dogfood.AspNet`) +
  `.csproj` (renamed file + RootNamespace, unreachable
  System.Text.RegularExpressions dep appended).

Added for the dogfood: Dockerfile + k8s.yaml + .env.example,
`.deptex/{expected.yaml,deploy.sh,SOURCE.md}`, README rewritten. No
malicious-pkg seed for nuget pre-walkthrough.

Upstream fixture stays byte-stable per Patch B.
