package com.example;

import com.fasterxml.jackson.databind.ObjectMapper;

public class JacksonGadget {
    private final ObjectMapper mapper;

    public JacksonGadget() {
        // Safe Jackson config: no defaultTyping, no polymorphic gadget surface.
        this.mapper = new ObjectMapper();
    }

    public String parseFixed() {
        try {
            // Safe: hardcoded JSON — no taint reaches the sink.
            Object result = mapper.readValue("{\"ok\":true}", Object.class);
            return "parsed: " + result.toString();
        } catch (Exception e) {
            return "error";
        }
    }
}
