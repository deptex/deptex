package com.example;

import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.beans.BeanWrapperImpl;

@RestController
public class BindController {

    @PostMapping("/bind")
    public String bind(@RequestParam String value) {
        BeanWrapperImpl wrapper = new BeanWrapperImpl(new Target());
        // Safe: the property PATH is a fixed constant; only the bound VALUE is
        // tainted (arg 1). Spring4Shell requires the PATH (arg 0) to be
        // attacker-controlled, so setPropertyValue's argument_indices: [0] must
        // NOT fire here. Under the old `argument_indices: []` ("any tainted arg
        // fires") this benign data-binding call was a code_injection false
        // positive.
        wrapper.setPropertyValue("displayName", value);
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
