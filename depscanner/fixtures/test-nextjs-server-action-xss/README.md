# test-nextjs-server-action-xss

Next.js App-Router server action that returns user-controlled HTML
without sanitisation.

- **Ecosystem:** npm
- **Framework:** Next.js (App Router server action)
- **Vulnerable dep:** `next==13.4.0` + a deliberately old
  `dompurify==2.0.10`.
- **Reachable handler:** `app/actions/echo.ts:echoAction()` — form
  field value flows through `dangerouslySetInnerHTML`.
- **Unreachable handler:** `app/actions/safe.ts:safeAction()` — wraps a
  literal string.

Expected snapshot: next.js entry-point row + semgrep XSS finding on
`echoAction`.
