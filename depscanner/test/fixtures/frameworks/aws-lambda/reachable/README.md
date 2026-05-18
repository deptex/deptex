# aws-lambda / reachable — CVE-2021-44906 (minimist prototype pollution)

- **Vulnerable dep:** `minimist@1.2.5`
- **Sink:** `index.js:8` — `minimist(args)` on user-controlled tokens from `event.body`.
- **Entry point:** `exports.handler` AWS Lambda export.
- **Expected verdict:** `data_flow`.
