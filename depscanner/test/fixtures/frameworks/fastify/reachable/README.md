# fastify / reachable — CVE-2019-10744 (lodash defaultsDeep prototype pollution)

- **Vulnerable dep:** `lodash@4.17.11`
- **Sink:** `index.js:9` — `_.defaultsDeep(target, req.body)` pollutes `Object.prototype` via attacker-controlled keys (`__proto__`, `constructor`).
- **Entry point:** `app.post('/merge', ...)`.
- **Expected verdict:** `confirmed` or `data_flow`.
