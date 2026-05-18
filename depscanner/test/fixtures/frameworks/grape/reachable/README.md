# grape / reachable — CVE-2018-3769 (XSS via JSONP)

- **Vulnerable dep:** `grape 1.0.2`
- **Sink:** `api.rb:9` — `{ msg: params[:msg] }` reflected through JSONP-capable Grape formatter.
- **Entry point:** `get "/echo"` Grape endpoint.
- **Expected verdict:** `data_flow`.
