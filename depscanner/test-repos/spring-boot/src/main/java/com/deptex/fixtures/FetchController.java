package com.deptex.fixtures;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

import java.io.InputStream;
import java.net.URL;

@RestController
@RequestMapping("/fetch")
public class FetchController {

    private final RestTemplate restTemplate = new RestTemplate();

    @GetMapping("/stream")
    public String stream(@RequestParam String target) throws Exception {
        // REACHABLE: ssrf — attacker-controlled URL opened directly.
        URL url = new URL(target);
        InputStream in = url.openStream();
        in.close();
        return "ok";
    }

    @GetMapping("/proxy")
    public String proxy(@RequestParam String endpoint) {
        // REACHABLE: ssrf — tainted URL fetched via RestTemplate.
        String body = restTemplate.getForObject(endpoint, String.class);
        return "ok";
    }
}
