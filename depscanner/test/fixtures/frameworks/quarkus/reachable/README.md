# quarkus / reachable — CVE-2023-2974 (resteasy-client SSRF)

- **Vulnerable dep:** `io.quarkus:quarkus-resteasy:2.16.6.Final`
- **Sink:** `ProxyResource.java:19` — `client.target(url).request().get` with user-controlled URL.
- **Entry point:** `@Path("/proxy")` + `@GET`.
- **Expected verdict:** `data_flow`.
