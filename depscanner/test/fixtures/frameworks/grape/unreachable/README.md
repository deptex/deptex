# grape / unreachable — CVE-2018-3769

- **Vulnerable dep:** `grape 1.0.2` (class declared, no endpoints).
- **Why unreachable:** zero `get`/`post` declarations; no params reflected.
- **Expected verdict:** `module`.
