# micronaut / reachable — CVE-2023-25569 (HTTP/2 reset DoS)

- **Vulnerable dep:** `io.micronaut:micronaut-http-server:3.7.4`
- **Sink:** `EchoController.java:17` — reflected input on `@Get` route.
- **Entry point:** `@Controller("/echo")` + `@Get`.
- **Expected verdict:** `data_flow`.
