package com.deptex;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.text.StringSubstitutor;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class App {
    private static final Logger logger = LogManager.getLogger(App.class);

    public static void processInput(String userInput) {
        // Log4Shell CVE-2021-44228 reachability target.
        logger.info("Processing: {}", userInput);
        logger.error("Error for: " + userInput);
    }

    public static Object deserialize(String json) throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        // Jackson default-typing enablement — surface for polymorphic deserialization CVEs.
        mapper.enableDefaultTyping();
        return mapper.readValue(json, Object.class);
    }

    public static String interpolate(String template) {
        // Text4Shell CVE-2022-42889.
        StringSubstitutor sub = StringSubstitutor.createInterpolator();
        return sub.replace(template);
    }

    public static void main(String[] args) throws Exception {
        String input = args.length > 0 ? args[0] : "test";
        processInput(input);
        deserialize("{\"key\":\"value\"}");
        interpolate("Hello ${env:USER}");
    }
}
