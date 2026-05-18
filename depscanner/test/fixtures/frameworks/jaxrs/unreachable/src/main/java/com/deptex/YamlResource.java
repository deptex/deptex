package com.deptex;

import jakarta.ws.rs.Path;

/**
 * Resource class with a @Path annotation but no method-level @GET/@POST/etc.
 * No HTTP entry point reaches snakeyaml.
 */
@Path("/yaml")
public class YamlResource {
    public String dump() {
        return "no entry point";
    }
}
