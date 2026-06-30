package com.example;

import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.beans.BeanWrapperImpl;

@RestController
public class BindController {

    @PostMapping("/bind")
    public String bind(@RequestParam String prop, @RequestParam String value) {
        BeanWrapperImpl wrapper = new BeanWrapperImpl(new Target());
        // Spring4Shell (CVE-2022-22965): the attacker controls the property
        // PATH (arg 0) — e.g. "class.module.classLoader.resources.context...".
        // setPropertyValue is modelled with argument_indices: [0], so this
        // tainted-path call must emit a code_injection flow.
        wrapper.setPropertyValue(prop, value);
        return "ok";
    }
}

class Target {
    private String displayName;

    public void setDisplayName(String n) {
        this.displayName = n;
    }

    public String getDisplayName() {
        return displayName;
    }
}
