package com.deptex;

import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Get;
import io.micronaut.http.annotation.QueryValue;

/**
 * CVE-2023-25569 (proxy) — Micronaut HTTP server <= 3.7.4 HTTP/2 reset DoS.
 * Reachability requires any HTTP entry point on the server.
 */
@Controller("/echo")
public class EchoController {

    @Get
    public String echo(@QueryValue("msg") String msg) {
        // Sink: reflect user input — drives dataflow analysis to see a flow.
        return "<msg>" + msg + "</msg>";
    }
}
