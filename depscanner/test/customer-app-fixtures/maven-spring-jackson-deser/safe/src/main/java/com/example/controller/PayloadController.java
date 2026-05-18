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
        // Patched: never deserialize attacker JSON. Coerce to an int id and
        // look up a server-side payload from a fixed catalog.
        auditService.record(payload);
        int lookupId = Integer.parseInt(payload);
        return payloadService.parseFor(lookupId);
    }
}
