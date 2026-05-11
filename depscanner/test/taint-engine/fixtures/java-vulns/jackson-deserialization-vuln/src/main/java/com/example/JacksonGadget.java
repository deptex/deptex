package com.example;

import com.fasterxml.jackson.databind.ObjectMapper;

public class JacksonGadget {
    private final ObjectMapper mapper;

    public JacksonGadget() {
        this.mapper = new ObjectMapper();
        // Dangerous config: turning on defaultTyping makes readValue accept
        // a class-name discriminator inside the JSON payload, which is the
        // gadget-chain trigger for CVE-2017-7525 and its descendants.
        this.mapper.enableDefaultTyping();
    }

    public String parse(String json) {
        try {
            // Sink: ObjectMapper.readValue with attacker-controlled JSON +
            // defaultTyping = polymorphic deserialization RCE.
            Object result = mapper.readValue(json, Object.class);
            return "parsed: " + result.toString();
        } catch (Exception e) {
            return "error";
        }
    }
}
