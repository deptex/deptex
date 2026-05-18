# tornado / unreachable — CVE-2023-28370

- **Vulnerable dep:** `tornado==6.2` (used, no redirect call).
- **Why unreachable:** only `self.write` is called; redirect sink absent.
- **Expected verdict:** `module`.
