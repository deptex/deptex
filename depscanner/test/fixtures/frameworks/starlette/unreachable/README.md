# starlette / unreachable — CVE-2023-29159

- **Vulnerable dep:** `starlette==0.27.0` (used, but no `RedirectResponse`).
- **Why unreachable:** routes only return `PlainTextResponse`; the open-redirect sink is absent.
- **Expected verdict:** `module`.
