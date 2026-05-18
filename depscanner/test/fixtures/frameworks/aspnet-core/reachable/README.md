# aspnet-core / reachable — CVE-2023-36038 (Form parsing DoS)

- **Vulnerable dep:** `Microsoft.AspNetCore.App@7.0.10`
- **Sink:** `Controllers/UploadController.cs:13` — `[FromForm] IFormCollection` triggers vulnerable Form parser.
- **Entry point:** `[ApiController]` + `[HttpPost]`.
- **Expected verdict:** `data_flow`.
