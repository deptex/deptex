package com.example;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Safe counterpart of jackson-deserialization-vuln.
 *
 * Endpoint has no body binding — no @RequestBody, no @RequestParam — so
 * no tainted string can ever reach JacksonGadget.parse(). The Jackson sink
 * is still present in the project but unreachable from any HTTP entry
 * point.
 */
@RestController
public class IngestController {
    private final JacksonGadget gadget;

    public IngestController(JacksonGadget gadget) {
        this.gadget = gadget;
    }

    @PostMapping("/ingest")
    public String ingest() {
        // Safe: hardcoded constant — no taint flows here.
        return gadget.parseFixed();
    }
}
