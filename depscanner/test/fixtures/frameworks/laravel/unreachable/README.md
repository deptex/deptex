# laravel / unreachable — CVE-2021-43808

- **Vulnerable dep:** `laravel/framework 8.40.0` (declared, no `Route::*` calls).
- **Why unreachable:** zero routes; the application surface is empty.
- **Expected verdict:** `module`.
