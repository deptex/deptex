# SOURCE

Standalone copy of upstream taint-engine fixture:

- **Upstream path:** `depscanner/fixtures/test-laravel-sqli-php/`
- **Upstream tree SHA at copy time:** `6589206219726f5989acc126cca7b2f6663fa3f5`
- **Files copied verbatim:** `composer.json` (renamed package +
  league/flysystem unreachable dep appended) +
  `app/Http/Controllers/UserController.php`.

Added for the dogfood: Dockerfile + k8s.yaml + .env.example,
`.deptex/{expected.yaml,deploy.sh,SOURCE.md}`, README rewritten. No
malicious-pkg seed for composer pre-walkthrough — iterated in M5.

Upstream fixture stays byte-stable per Patch B.
