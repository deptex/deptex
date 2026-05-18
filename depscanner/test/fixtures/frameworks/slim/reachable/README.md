# slim / reachable — CVE-2019-12867 (header injection)

- **Vulnerable dep:** `slim/slim 3.12.1`
- **Sink:** `index.php:15` — `$res->withHeader('Location', $target)` with user-controlled URL.
- **Entry point:** `$app->get('/redirect', ...)`.
- **Expected verdict:** `data_flow`.
