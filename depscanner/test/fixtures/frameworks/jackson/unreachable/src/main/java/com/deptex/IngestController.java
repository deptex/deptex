package com.deptex;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Same dep version, no taint path. The controller takes no request input
 * and the readValue call operates on a hardcoded constant — the polymorphic
 * deserialization sink is present but unreachable, and `enableDefaultTyping`
 * is never called.
 */
@RestController
public class IngestController {

    private final ObjectMapper mapper = new ObjectMapper();

    @GetMapping("/health")
    public String health() throws Exception {
        // Hardcoded literal — no taint reaches the sink.
        Object parsed = mapper.readValue("{\"ok\":true}", Object.class);
        return "parsed: " + parsed;
    }
}
