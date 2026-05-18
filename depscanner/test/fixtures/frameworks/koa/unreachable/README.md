# koa / unreachable — CVE-2017-16026 (request SSRF)

- **Vulnerable dep:** `request@2.81.0` (in package.json, never imported in source).
- **Why unreachable:** no source file references `request`; SBOM lists the dep but tree-sitter usage extraction finds zero call sites.
- **Expected verdict:** `module` or `unreachable`.
