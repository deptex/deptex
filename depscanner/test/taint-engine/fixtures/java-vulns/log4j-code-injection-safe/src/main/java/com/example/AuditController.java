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
        // Safe: the real Log4j logger only ever sees a constant. The tainted
        // User-Agent does reach `metrics.info(...)` / `tracker.log(...)`, but
        // those are NON-LOGGER receivers the engine's loggerSinkSuppressed
        // guard drops — so no Log4Shell (code_injection) flow is emitted.
        return audit.record(ua);
    }
}
