package com.deptex;

import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import org.yaml.snakeyaml.Yaml;

/**
 * CVE-2022-1471 — snakeyaml <= 1.33 unsafe Yaml.load deserialization.
 * Reachable via a JAX-RS @POST endpoint that loads attacker-controlled YAML.
 */
@Path("/yaml")
public class YamlResource {

    @POST
    @Produces(MediaType.TEXT_PLAIN)
    public String load(String body) {
        // Sink: Yaml.load on user-controlled string.
        Object o = new Yaml().load(body);
        return String.valueOf(o);
    }
}
