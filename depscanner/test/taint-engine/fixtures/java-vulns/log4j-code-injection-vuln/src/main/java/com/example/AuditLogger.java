package com.example;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class AuditLogger {
    private static final Logger logger = LogManager.getLogger(AuditLogger.class);

    public String record(String userAgent) {
        // Sink: tainted UA reaches Log4j Logger.info — JNDI lookup
        // substitution executes attacker-controlled bytecode.
        logger.info(userAgent);
        return "logged";
    }
}
