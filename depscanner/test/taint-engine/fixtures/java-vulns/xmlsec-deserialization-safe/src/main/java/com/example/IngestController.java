package com.example;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Safe counterpart to xmlsec-deserialization-vuln. The controller does not
 * accept any tainted source — the bytes signed are a hard-coded literal.
 * No Spring source annotation, so the engine must emit zero
 * `deserialization` flows.
 */
@RestController
public class IngestController {
    private static final byte[] LITERAL = "<doc/>".getBytes();
    private final XmlSigner signer;

    public IngestController(XmlSigner signer) {
        this.signer = signer;
    }

    @PostMapping("/sign-literal")
    public String sign() {
        return signer.sign(LITERAL);
    }
}
