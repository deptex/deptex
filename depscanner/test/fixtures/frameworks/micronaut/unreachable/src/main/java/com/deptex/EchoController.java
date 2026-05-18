package com.deptex;

import io.micronaut.http.annotation.Controller;

/**
 * Controller class declared with @Controller but no @Get/@Post route methods.
 * No HTTP entry points exist; HTTP/2 reset surface unreachable.
 */
@Controller("/echo")
public class EchoController {
    public String unused() {
        return "no route";
    }
}
