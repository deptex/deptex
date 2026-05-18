package com.deptex;

import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.client.Client;
import jakarta.ws.rs.client.ClientBuilder;

/**
 * CVE-2023-2974 — quarkus-core 2.16.6.Final TLS hostname mismatch /
 * resteasy-client SSRF via user-controlled URL.
 */
@Path("/proxy")
public class ProxyResource {

    @GET
    public String fetch(@QueryParam("url") String url) {
        Client client = ClientBuilder.newClient();
        // Sink: HTTP request to attacker-controlled URL.
        return client.target(url).request().get(String.class);
    }
}
