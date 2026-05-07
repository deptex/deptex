# Ruby fixtures — taint-engine

Per-fixture pairs (`-vuln` / `-safe`) cover the framework specs the engine
ships with:

- `rails-sql-injection-{vuln,safe}` — controller `def search` style; vuln does
  raw `where("...#{q}...")`, safe coerces via `Integer()` and uses bound `find_by`.
- `rails-command-injection-{vuln,safe}` — controller `def export` style;
  vuln pipes `params[:filename]` to backticks, safe sanitizes via `Shellwords`.
- `sinatra-sql-injection-{vuln,safe}` — `class App < Sinatra::Base` with
  `get '/users' do ... end` route DSL. Vuln calls `User.where("name = '#{q}'")`
  in a helper module; safe calls the non-sink `User.find_by(name: name)`.
- `sinatra-xss-{vuln,safe}` — same Sinatra DSL shape, with `raw(body)`
  sink in a helper module. Safe escapes via `CGI.escapeHTML` before passing
  the value across the file boundary.

The Sinatra fixtures exercise the route-block lowering in the Ruby
callgraph (`src/taint-engine/ruby/callgraph.ts`): for any class extending
`Sinatra::Base` / `Sinatra::Application`, every HTTP-verb DSL call with a
trailing `do ... end` / `{ ... }` block is collected as a synthetic
instance method on the class. The block body becomes the method body and
is lowered like any other Ruby method.

Hanami / Roda / Padrino share the same DSL shape (HTTP-verb call on a
known base class) and could be added by extending the
`SINATRA_BASE_CLASSES` / `SINATRA_HTTP_VERBS` constants.
