package com.example;

import org.apache.xml.security.signature.XMLSignature;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Safe counterpart to receiver-taint-propagation-vuln: no Spring source
 * annotation on the handler parameter, so `keyData` is just a local with
 * no taint. The same receiver-chain shape MUST emit zero flows — the
 * propagation rule only fires when the receiver is an existing tainted
 * local, never on plain locals or constants.
 */
@RestController
public class IngestController {
    private static final String LITERAL = "<doc/>";
    private final XMLSignature signature;

    public IngestController(XMLSignature signature) {
        this.signature = signature;
    }

    @PostMapping("/sign-literal")
    public String sign() throws Exception {
        // Same `.toString().getBytes()` receiver chain as the vuln
        // variant, but the receiver is a compile-time constant.
        byte[] bytes = LITERAL.toString().getBytes();
        signature.sign(bytes);
        return "signed";
    }
}
