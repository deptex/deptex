# fastify / unreachable — CVE-2019-10744 (lodash defaultsDeep prototype pollution)

- **Vulnerable dep:** `lodash@4.17.11` (imported, no vulnerable sink reached).
- **Why unreachable:** only `_.uniq` is used. The vulnerable family (defaultsDeep / merge / set) is never called.
- **Expected verdict:** `module`.
