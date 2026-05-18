# spring / reachable — CVE-2022-22965 (Spring4Shell)

- **Vulnerable dep:** `org.springframework:spring-webmvc:5.3.16`
- **Sink:** `GreetingController.java:21` — `@PostMapping` with `@RequestBody Greeting g` enables the class-loader chain.
- **Entry point:** `@RestController` + `@PostMapping("/greet")`.
- **Expected verdict:** `data_flow`.
