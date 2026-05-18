# rails / reachable — CVE-2022-32224 (YAML.load deserialization)

- **Vulnerable dep:** `rails 6.1.4`
- **Sink:** `app/controllers/jobs_controller.rb:9` — `YAML.load(payload)` on user-controlled `params[:data]`.
- **Entry point:** `config/routes.rb` exposes `POST /jobs` → `JobsController#create`.
- **Expected verdict:** `data_flow`.
