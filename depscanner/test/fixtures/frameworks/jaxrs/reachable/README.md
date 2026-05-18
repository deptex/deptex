# jaxrs / reachable — CVE-2022-1471 (snakeyaml deserialization)

- **Vulnerable dep:** `org.yaml:snakeyaml:1.30`
- **Sink:** `YamlResource.java:18` — `new Yaml().load(body)` on user-controlled string.
- **Entry point:** `@Path("/yaml")` + `@POST`.
- **Expected verdict:** `data_flow`.
