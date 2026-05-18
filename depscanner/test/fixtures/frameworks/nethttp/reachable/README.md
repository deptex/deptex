# nethttp / reachable — CVE-2022-32149 (golang.org/x/text DoS)

- **Vulnerable dep:** `golang.org/x/text v0.3.7`
- **Sink:** `main.go:15` — `language.ParseAcceptLanguage(req.Header.Get(...))`.
- **Entry point:** `http.HandleFunc("/lang", ...)` + `http.ListenAndServe`.
- **Expected verdict:** `data_flow`.
