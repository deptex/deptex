# nestjs / reachable — CVE-2022-24999 (qs prototype pollution / DoS)

- **Vulnerable dep:** `qs@6.5.2`
- **Sink:** `src/app.controller.ts:12` — `qs.parse(q)`.
- **Entry point:** `@Get('/parse')` decorator on `AppController.parse`.
- **Expected verdict:** `data_flow`.
