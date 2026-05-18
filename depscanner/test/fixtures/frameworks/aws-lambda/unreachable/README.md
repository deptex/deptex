# aws-lambda / unreachable — CVE-2021-44906 (minimist)

- **Vulnerable dep:** `minimist@1.2.5` (declared, never imported).
- **Why unreachable:** handler returns a static OK and never parses any args.
- **Expected verdict:** `module` or `unreachable`.
