# test-sinatra-xss-gem

Sinatra app with one reachable reflected XSS via ERB.

- **Ecosystem:** rubygems
- **Framework:** Sinatra + ERB
- **Vulnerable shape:** ERB interpolation of `params[:msg]` without
  HTML escaping. CWE-79 / generic reflected XSS.
- **Reachable handler:** `app.rb:/echo` — `erb "<%= params[:msg] %>"`.
- **Unreachable handler:** `app.rb:/safe` — uses `h(...)` helper.

Expected snapshot: sinatra entry point detected, semgrep XSS finding
on `/echo`.

Note: the Sinatra framework spec is currently parked per the
reachability roadmap; this fixture locks the deps + entry point shape
so a future spec change is regression-tested end to end.
