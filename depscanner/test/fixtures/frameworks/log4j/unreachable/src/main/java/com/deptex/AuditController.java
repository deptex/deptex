package com.deptex;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

/**
 * Same dep pin as reachable/, but the User-Agent value never flows into the
 * logger. The handler logs only a hard-coded constant. Log4j is still on
 * the classpath, so the dep-scan VDR will still attribute CVE-2021-44228;
 * the reachability classifier should downgrade to `module` since no flow
 * connects an HTTP source to a Log4j sink.
 */
@RestController
public class AuditController {

    private static final Logger logger = LogManager.getLogger(AuditController.class);

    @GetMapping("/audit")
    public String audit(@RequestHeader("User-Agent") String ua) {
        // Safe: tainted UA is unused. Logger receives a constant.
        logger.info("audit endpoint hit");
        return "ok";
    }
}
