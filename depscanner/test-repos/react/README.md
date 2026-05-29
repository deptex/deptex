# react

Greenfield React SPA reference fixture. Pure-frontend; no server, no DAST
cell. Exercises the dependency / reachability / IaC / container / secrets
/ malicious-pkg / Semgrep scanners through a realistic single-page app
that imports a small set of widely-used libraries and exposes one
intentional client-side taint sink.

- **Ecosystem:** npm
- **Framework:** React 18 SPA (Vite-style index.html + module entry)
- **Reachable vuln dep:** `lodash@4.17.20` — `_.template()` invoked from
  `src/App.jsx` with `?tpl=` query-string user input. Same CVE shape as
  the express fixture's reachable seed but exercised through a different
  framework and trust boundary.
- **Unreachable vuln deps:** `moment@2.29.1` and `axios@0.21.0` are
  declared but only `axios` is imported. `moment` is unreferenced → the
  tree-sitter usage extractor reports zero usages → classifier marks
  it unreachable.
- **Historical-malicious:** `event-stream==3.3.6` (per
  `.github/dependabot.yml` exclusion).
- **No DAST cell.** The Dockerfile serves the static build via an
  nginx stub purely so the container + IaC scanners have something to
  bite on. Static SPAs have no meaningful DAST surface in this corpus.

See `.deptex/SOURCE.md` for provenance, `.deptex/expected.yaml` for the
canonical expected-finding list.
