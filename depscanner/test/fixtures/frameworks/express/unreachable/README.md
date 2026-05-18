# express / unreachable — CVE-2021-23337 (lodash template injection)

- **Vulnerable dep:** `lodash@4.17.20` (imported, NOT exercised on the vulnerable path).
- **CVE:** CVE-2021-23337.
- **Why unreachable:** only `_.chunk` is invoked. The vulnerable `_.template` API is never reached from any Express route.
- **Expected verdict:** `reachability_level=module` (dep is present, no taint flow to a CVE sink).
