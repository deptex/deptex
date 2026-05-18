package com.example;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

/**
 * CVE-2022-42889-shaped vulnerable fixture ("Text4Shell").
 *
 * Spring REST controller accepts a raw String via @RequestBody and hands
 * it to TextRenderer.render(...) — which calls Apache Commons Text
 * StringSubstitutor.replace on attacker-controlled bytes. commons-text
 * 1.5–1.9's default lookup set includes a Nashorn `script` lookup that
 * executes the substituted JavaScript.
 */
@RestController
public class IngestController {
    private final TextRenderer renderer;

    public IngestController(TextRenderer renderer) {
        this.renderer = renderer;
    }

    @PostMapping("/render")
    public String render(@RequestBody String body) {
        // Source: @RequestBody String — tainted by Spring spec.
        // Cross-file: renderer.render() is the actual sink call site.
        return renderer.render(body);
    }
}
