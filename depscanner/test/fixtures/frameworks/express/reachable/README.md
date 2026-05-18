# express / reachable — CVE-2021-23337 (lodash template injection)

- **Vulnerable dep:** `lodash@4.17.20`
- **CVE:** CVE-2021-23337 — `_.template` evaluates user-controlled strings as JS.
- **Sink:** `src/render.js` line 5 — `_.template(tmpl)({})`.
- **Entry point:** `index.js` line 7 — `app.post('/', ...)` reads `req.body.template`.
- **Expected verdict:** `reachability_level=confirmed` (CVE-targeted spec exists for this dep + sink) or `data_flow`.
