package com.example.controller;

import com.example.service.PayloadService;
import com.example.service.AuditService;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

@RestController
public class PayloadController {
    private final PayloadService payloadService;
    private final AuditService auditService;

    public PayloadController(PayloadService payloadService, AuditService auditService) {
        this.payloadService = payloadService;
        this.auditService = auditService;
    }

    @PostMapping("/payload")
    public Object ingestPayload(@RequestParam String payload) {
        // Customer-shape: hand the raw user payload through the service layer
        // to Jackson's ObjectMapper.readValue with a polymorphic root type —
        // CVE-2017-7525 family (Jackson deserialization gadget chain).
        auditService.record(payload);
        return payloadService.parse(payload);
    }
}
