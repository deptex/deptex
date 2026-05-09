package com.deptex;

import jakarta.ws.rs.Path;

/**
 * Resource class declared but no @GET/@POST methods — no HTTP entry,
 * resteasy-client never invoked.
 */
@Path("/proxy")
public class ProxyResource {
    public String unused() {
        return "no entry";
    }
}
