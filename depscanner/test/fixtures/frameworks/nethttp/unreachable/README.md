# nethttp / unreachable — CVE-2022-32149

- **Vulnerable dep:** `golang.org/x/text v0.3.7` (declared, not imported in source).
- **Why unreachable:** no `language.ParseAcceptLanguage` call, no HandleFunc.
- **Expected verdict:** `module` or `unreachable`.
