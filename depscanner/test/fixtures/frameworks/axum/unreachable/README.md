# axum / unreachable — CVE-2024-32650

- **Vulnerable dep:** `axum = "0.6.0"` (constructed, never served).
- **Why unreachable:** no routes, no `axum::Server::bind`.
- **Expected verdict:** `module`.
