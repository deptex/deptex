# test-laravel-sqli-php

Tiny Laravel controller with one raw-SQL injection via
`DB::select(DB::raw($input))`.

- **Ecosystem:** packagist
- **Framework:** Laravel
- **Vulnerable shape:** `DB::raw` with user-controlled string.
- **Reachable handler:** `UserController.php:search()` — request input
  concatenated.
- **Unreachable handler:** `UserController.php:show()` — uses Eloquent
  `find($id)` (parameterised).

Expected snapshot: laravel deps in `deps.json`, semgrep + entry-point
rows for `search()` only.
