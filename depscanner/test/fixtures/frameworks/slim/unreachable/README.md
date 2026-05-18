# slim / unreachable — CVE-2019-12867

- **Vulnerable dep:** `slim/slim 3.12.1` (instantiated, no routes).
- **Why unreachable:** zero `$app->get|post|...` calls.
- **Expected verdict:** `module`.
