package com.example.service;

import com.fasterxml.jackson.databind.ObjectMapper;

public class PayloadService {
    private final ObjectMapper mapper;

    public PayloadService() {
        this.mapper = new ObjectMapper();
    }

    public Object parse(String payload) throws Exception {
        // Sink: ObjectMapper.readValue against Object.class with no PTV =
        // unsafe polymorphic deserialization (CVE-2017-7525).
        return mapper.readValue(payload, Object.class);
    }
}
