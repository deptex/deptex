package com.example;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Safe counterpart of commons-text-code-injection-vuln.
 *
 * Endpoint has no body binding — no @RequestBody, no @RequestParam — so
 * no tainted string can ever reach TextRenderer.renderFixed(). The
 * commons-text StringSubstitutor sink is still present in the project
 * but unreachable from any HTTP entry point.
 */
@RestController
public class IngestController {
    private final TextRenderer renderer;

    public IngestController(TextRenderer renderer) {
        this.renderer = renderer;
    }

    @PostMapping("/render")
    public String render() {
        // Safe: hardcoded constant — no taint flows here.
        return renderer.renderFixed();
    }
}
