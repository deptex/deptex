# warp / unreachable — CVE-2023-26964

- **Vulnerable dep:** `warp = "0.3.3"` (declared, not imported).
- **Why unreachable:** no filters, no `warp::serve` invocation.
- **Expected verdict:** `module` or `unreachable`.
