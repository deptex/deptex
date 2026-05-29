# nextjs

Next.js App-Router server action that returns user-controlled HTML
without sanitisation. Stand-alone copy of the upstream taint-engine
fixture `depscanner/fixtures/test-nextjs-server-action-xss/` layered
with dogfood-only categories (IaC, container, secrets, malicious-pkg)
so a single dogfood scan exercises every scanner end-to-end.

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
- **Historical-malicious:** `event-stream==3.3.6` (per
  `.github/dependabot.yml` exclusion).

See `.deptex/SOURCE.md` for upstream provenance, `.deptex/expected.yaml`
for the canonical expected-finding list, and `.deptex/deploy.sh` to
boot the fixture for DAST.
