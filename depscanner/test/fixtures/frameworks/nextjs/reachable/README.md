# nextjs / reachable — CVE-2024-21505 (Next.js SSRF / open-redirect)

- **Vulnerable dep:** `next@14.0.0`
- **Sink:** `pages/api/redirect.js:9` — `NextResponse.redirect(target)` with attacker-controlled URL.
- **Entry point:** Next.js API route at `/api/redirect`.
- **Expected verdict:** `data_flow`.
