package com.example;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class AuditLogger {
    private static final Logger logger = LogManager.getLogger(AuditLogger.class);
    private MetricsClient metrics;
    private EventTracker tracker;

    public String record(String userAgent) {
        // Safe: hardcoded constant — no taint reaches the logger.
        logger.info("audit endpoint hit");

        // T2 guard proof. The tainted User-Agent flows into `.info(...)` /
        // `.log(...)` — method names the log4j wildcard sinks (`*.info(*)` /
        // `*.log(*)`) match — but on NON-LOGGER receivers (`metrics`, `tracker`:
        // neither name contains "log"). `loggerSinkSuppressed` must suppress
        // both, so this fixture emits zero code_injection flows. Under the old
        // bare-wildcard `argument_indices: []` matching each produced a
        // Log4Shell false positive.
        metrics.info(userAgent);
        tracker.log(userAgent);
        return "logged";
    }
}

// Minimal non-logger collaborators. Their method names collide with logger
// levels but their receiver names do not look like a logger.
class MetricsClient {
    public void info(String message) {
        // no-op metric counter; not a logger
    }
}

class EventTracker {
    public void log(String event) {
        // no-op audit trail; not a logger
    }
}
