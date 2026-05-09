# sinatra / unreachable — CVE-2024-21510

- **Vulnerable dep:** `sinatra 2.2.0` (required, no routes).
- **Why unreachable:** zero `get`/`post` blocks; no send_file call.
- **Expected verdict:** `module`.
