package com.deptex;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

/**
 * CVE-2022-22965 — "Spring4Shell" RCE in spring-webmvc <= 5.3.17.
 * Triggered when a controller accepts a POJO via @RequestBody / form binding
 * and the request can override class.module.classLoader.* properties.
 */
@RestController
public class GreetingController {

    public static class Greeting {
        public String name;
    }

    @PostMapping("/greet")
    public String greet(@RequestBody Greeting g) {
        // Sink: data binding into POJO is the entry to the Spring4Shell chain.
        return "hello " + g.name;
    }
}
