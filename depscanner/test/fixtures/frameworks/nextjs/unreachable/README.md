# nextjs / unreachable — CVE-2024-21505

- **Vulnerable dep:** `next@14.0.0` (declared, but only a static `pages/index.js` exists; no API route).
- **Why unreachable:** zero `pages/api/*` handlers and no `NextResponse.redirect` call sites.
- **Expected verdict:** `module`.
