package com.example.service;

import com.fasterxml.jackson.databind.ObjectMapper;

public class PayloadService {
    private static final String[] CATALOG = new String[] {
        "{\"kind\":\"none\"}",
        "{\"kind\":\"hello\"}",
    };
    private final ObjectMapper mapper;

    public PayloadService() {
        this.mapper = new ObjectMapper();
    }

    public Object parseFor(int lookupId) throws Exception {
        // The argument to readValue is a server-controlled string from a
        // fixed catalog — no taint reaches the deser sink.
        String json = CATALOG[lookupId % CATALOG.length];
        return mapper.readValue(json, Object.class);
    }
}
