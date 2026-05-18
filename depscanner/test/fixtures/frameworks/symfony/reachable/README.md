# symfony / reachable — CVE-2024-50340 (env override via query)

- **Vulnerable dep:** `symfony/runtime 6.3.0`
- **Sink:** `src/Controller/EnvController.php:21` — `getenv($name)` from query.
- **Entry point:** `#[Route('/env')]` controller method.
- **Expected verdict:** `data_flow`.
