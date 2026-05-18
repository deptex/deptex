package com.example;

import org.apache.commons.text.StringSubstitutor;

public class TextRenderer {
    public String renderFixed() {
        // Safe: only string literals reach StringSubstitutor.replace. No
        // tainted bytes flow into the substitution surface.
        return StringSubstitutor.replace("Hello ${name}", "name", "world");
    }
}
