# nextjs

Next.js App-Router server action that returns user-controlled HTML
without sanitisation. Stand-alone copy of the upstream taint-engine
fixture `depscanner/fixtures/test-nextjs-server-action-xss/` layered
with dogfood-only categories (IaC, container, secrets) so a single
dogfood scan exercises the scanners end-to-end.

- **Ecosystem:** npm
- **Framework:** Next.js (App Router server action)
- **Reachable vuln dep:** `next==13.4.0` (multiple advisories — at least
  one expected per `.deptex/expected.yaml`).
- **Unreachable vuln dep:** `dompurify==2.0.10` — declared in
  `package.json` but never imported anywhere in the fixture, so the
  tree-sitter usage extractor reports zero usages and the
  reachability classifier marks it unreachable.
- **Reachable taint flow:** `app/actions/echo.ts:echoAction()` →
  `app/page.tsx` via `dangerouslySetInnerHTML`.
- **Unreachable taint flow:** `app/actions/safe.ts:safeAction()` —
  wraps a literal string.
- **Malicious-pkg (deferred):** `event-stream==3.3.6` was seeded but is
  unpublished on npm (404), which aborts the whole install — removed from
  `package.json`. Malicious-package detection is exercised separately.

See `.deptex/SOURCE.md` for upstream provenance, `.deptex/expected.yaml`
for the canonical expected-finding list, and `.deptex/deploy.sh` to
boot the fixture for DAST.
