# sinatra / reachable — CVE-2024-21510 (path traversal via send_file)

- **Vulnerable dep:** `sinatra 2.2.0`
- **Sink:** `app.rb:7` — `send_file params[:p]`.
- **Entry point:** `get "/file"` route.
- **Expected verdict:** `data_flow`.
