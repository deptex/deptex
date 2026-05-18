package com.example;

import org.apache.commons.text.StringSubstitutor;

public class TextRenderer {
    public String render(String input) {
        // Sink: attacker-controlled bytes flow into the 3-arg
        // StringSubstitutor.replace(source, variableName, variableValue)
        // overload — commons-text 1.5–1.9 expands ${script:javascript:...}
        // lookups during substitution, which executes attacker-controlled
        // Nashorn script. Tainted value is at argument index 2 in this
        // overload, which is why the spec uses argument_indices=[] (any
        // tainted argument fires).
        return StringSubstitutor.replace("Hello ${input}", "input", input);
    }
}
