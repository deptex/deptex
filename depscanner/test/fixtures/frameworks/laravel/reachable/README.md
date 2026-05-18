# laravel / reachable — CVE-2021-43808 (mail rendering XSS)

- **Vulnerable dep:** `laravel/framework 8.40.0`
- **Sink:** `routes/web.php:11` — raw HTML response interpolating `$request->query('name')`.
- **Entry point:** `Route::get('/render', ...)`.
- **Expected verdict:** `data_flow`.
