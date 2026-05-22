# SOURCE

Standalone copy of upstream taint-engine fixture:

- **Upstream path:** `depscanner/fixtures/test-nextjs-server-action-xss/`
- **Upstream tree SHA at copy time:** `e39b40b13c9db9e90f6ec87263b7be07e7d45782`
- **Files copied verbatim:** `package.json`, `app/page.tsx`,
  `app/actions/echo.ts`, `app/actions/safe.ts`, `README.md` (then
  the README was rewritten for the dogfood framing).

The upstream fixture stays byte-stable per Patch B of the dogfood plan
(`.cursor/plans/depscanner-dogfood.plan.md`). This copy adds:

- `Dockerfile` + `k8s.yaml` for IaC + container scanner coverage
- `.env.example` for TruffleHog secrets coverage
- `event-stream@3.3.6` added to `package.json` for malicious-pkg coverage
- `package.json` `scripts.start` so the deploy.sh can boot the app
- `.deptex/{expected.yaml,deploy.sh,SOURCE.md}` for the dogfood harness

The reachable XSS sink (`echoAction → dangerouslySetInnerHTML`) and the
unreachable counterpart (`safeAction`) are unchanged.
