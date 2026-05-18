package com.example;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class AuditLogger {
    private static final Logger logger = LogManager.getLogger(AuditLogger.class);

    public String recordFixed() {
        // Safe: hardcoded constant — no taint reaches the logger.
        logger.info("audit endpoint hit");
        return "logged";
    }
}
