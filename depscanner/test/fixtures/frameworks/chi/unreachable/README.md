# chi / unreachable — CVE-2023-44487

- **Vulnerable dep:** `github.com/go-chi/chi/v5 v5.0.10` (router built, never served).
- **Why unreachable:** no routes registered, no HTTP listener.
- **Expected verdict:** `module`.
