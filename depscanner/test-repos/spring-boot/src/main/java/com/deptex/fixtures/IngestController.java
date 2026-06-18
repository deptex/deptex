package com.deptex.fixtures;

import com.fasterxml.jackson.databind.ObjectMapper;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.io.ByteArrayInputStream;
import java.io.ObjectInputStream;
import java.util.Base64;

@RestController
@RequestMapping("/ingest")
public class IngestController {

    private final ObjectMapper mapper = new ObjectMapper();

    @PostMapping("/json")
    public String json(@RequestBody String body) throws Exception {
        // REACHABLE: deserialization — untrusted JSON into Jackson with default typing.
        mapper.enableDefaultTyping();
        Object value = mapper.readValue(body, Object.class);
        return "ok";
    }

    @PostMapping("/object")
    public String object(@RequestParam String payload) throws Exception {
        // REACHABLE: deserialization — attacker bytes fed to ObjectInputStream.
        byte[] raw = Base64.getDecoder().decode(payload);
        ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(raw));
        Object obj = ois.readObject();
        return "ok";
    }
}
