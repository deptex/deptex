# rails

Greenfield Ruby on Rails dogfood fixture. No upstream taint-engine
fixture exists for the gem ecosystem; this is the gem reference for
the dogfood corpus.

- **Ecosystem:** gem
- **Framework:** Rails 6.0
- **Reachable vuln dep:** `rails 6.0.0` + `rack 2.0.6`.
- **Unreachable vuln dep:** `nokogiri 1.10.4` — declared but never
  required from `app/`.
- **Reachable handler:** `app/controllers/users_controller.rb:search`
  — `params[:name]` concatenated into a `find_by_sql` raw SQL string.
- **Unreachable handler:** `app/controllers/users_controller.rb:show`
  — `User.find` parameterised binding.
- **Malicious-pkg (deferred):** `rest-client 1.6.13` (the 2019 RubyGems
  compromise) was seeded but is yanked from RubyGems (404), which breaks
  `bundle` resolution — removed from the `Gemfile`. Malicious-package
  detection is exercised separately.

See `.deptex/SOURCE.md`.
