package com.deptex;

import org.springframework.stereotype.Component;

/**
 * Class is annotated as a Spring component but has no @RestController and
 * no @GetMapping/@PostMapping methods, so no HTTP entry point exists.
 * The Spring4Shell data-binding surface is unreachable.
 */
@Component
public class GreetingController {
    public String hello() {
        return "compile-time only";
    }
}
