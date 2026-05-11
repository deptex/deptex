package com.example;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

/**
 * CVE-2017-7525-shaped vulnerable fixture.
 *
 * Spring REST controller accepts a raw JSON String via @RequestBody and
 * hands it to JacksonGadget.parse(...) — which calls
 * ObjectMapper.readValue with defaultTyping enabled, opening the
 * polymorphic-deserialization gadget chain.
 */
@RestController
public class IngestController {
    private final JacksonGadget gadget;

    public IngestController(JacksonGadget gadget) {
        this.gadget = gadget;
    }

    @PostMapping("/ingest")
    public String ingest(@RequestBody String body) {
        // Source: @RequestBody String — tainted by Spring spec.
        // Cross-file: gadget.parse() is the actual sink call site.
        return gadget.parse(body);
    }
}
