# aiohttp / unreachable — CVE-2024-23334

- **Vulnerable dep:** `aiohttp==3.9.1` (used, no static handler).
- **Why unreachable:** no `add_static` / no `open(...)` on user input.
- **Expected verdict:** `module`.
