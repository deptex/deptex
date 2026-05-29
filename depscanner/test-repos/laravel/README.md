# laravel

Tiny Laravel controller with one raw-SQL injection via
`DB::select(DB::raw($input))`. Stand-alone copy of upstream taint-engine
fixture `depscanner/fixtures/test-laravel-sqli-php/` layered with
dogfood categories.

- **Ecosystem:** composer (packagist)
- **Framework:** Laravel
- **Reachable vuln dep:** `laravel/framework 8.6.11` +
  `guzzlehttp/guzzle 7.2.0`.
- **Unreachable vuln dep:** `league/flysystem 1.0.70` — declared but
  never imported.
- **Reachable handler:** `UserController.php:search()`.
- **Unreachable handler:** `UserController.php:show()`.

See `.deptex/SOURCE.md`.
