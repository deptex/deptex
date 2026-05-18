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
        // Vulnerable: User-Agent flows into Log4j Logger.info — Log4Shell
        // (CVE-2021-44228 family) substitutes ${jndi:...} lookups.
        return audit.record(ua);
    }
}
