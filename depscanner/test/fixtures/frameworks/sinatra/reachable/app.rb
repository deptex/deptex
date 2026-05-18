require "sinatra"

# CVE-2024-21510 — sinatra <= 2.2.0 path traversal via send_file with
# attacker-controlled filename.
get "/file" do
  # Sink: send_file on user-controlled path.
  send_file params[:p]
end
