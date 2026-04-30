# Ruby fixtures — taint-engine substrate gap

The Sinatra fixture pairs (`sinatra-sql-injection-{vuln,safe}` and
`sinatra-xss-{vuln,safe}`) are checked in but **not yet wired into**
`test/taint-engine-ruby.test.ts`.

**Why:** the Ruby callgraph (`src/taint-engine/ruby/callgraph.ts`) only
collects `method` and `singleton_method` AST nodes as function entry
points — i.e. `def foo` / `def self.foo`. Sinatra's idiomatic DSL puts
the request handler inside a route block:

```ruby
get '/users' do
  q = params[:q]
  ...
end
```

That `do ... end` is a `block` node, not a method definition, so the
substrate sees zero functions to analyze and emits zero flows for any
sinatra-style fixture even when the pattern matchers and specs are
correct. Confirmed against the live engine on 2026-04-29.

The committed sinatra fixtures faithfully capture how real Sinatra apps
are written — they will pass automatically once the Ruby substrate is
extended to lower `Sinatra::Base`-class route DSL blocks (or any block
attached to a Rack-style framework verb call) as synthetic methods on
the enclosing class. Until then, Rails fixtures (which use explicit
`def search` controller methods) are the only ruby-vulns we exercise.
