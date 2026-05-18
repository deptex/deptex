# fastapi / unreachable — CVE-2024-24762

- **Vulnerable dep:** `python-multipart==0.0.6` (declared, never invoked).
- **Why unreachable:** no route uses `Form()` / `File()` / `UploadFile`; multipart parser code path is dead.
- **Expected verdict:** `module`.
