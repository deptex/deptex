# rails / unreachable — CVE-2022-32224

- **Vulnerable dep:** `rails 6.1.4` (controller defined, no routes drawn).
- **Why unreachable:** `config/routes.rb` is empty; no HTTP entry to controller; no YAML.load.
- **Expected verdict:** `module`.
