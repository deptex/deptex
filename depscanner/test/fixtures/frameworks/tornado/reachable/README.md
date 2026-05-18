# tornado / reachable — CVE-2023-28370 (open redirect)

- **Vulnerable dep:** `tornado==6.2`
- **Sink:** `app.py:9` — `self.redirect(target)` with user-controlled URL.
- **Entry point:** `Application([(r"/redir", RedirectHandler)])`.
- **Expected verdict:** `data_flow`.
