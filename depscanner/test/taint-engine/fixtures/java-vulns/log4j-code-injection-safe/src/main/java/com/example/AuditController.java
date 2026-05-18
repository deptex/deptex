package com.example;

import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;

@RestController
public class AuditController {
    private final AuditLogger audit;

    public AuditController(AuditLogger audit) {
        this.audit = audit;
    }

    @GetMapping("/audit")
    public String audit(@RequestHeader("User-Agent") String ua) {
        // Safe: User-Agent value is dropped; we log only a constant.
        return audit.recordFixed();
    }
}
