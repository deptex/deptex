package com.example;

import org.apache.xml.security.signature.XMLSignature;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

/**
 * Exercises the receiver-taint propagation rule in propagate-core.ts.
 *
 * Shape mirrors the CVE-2023-44483 Qwen AI fixture: a tainted
 * String (`@RequestBody String keyData`) has a 0-arg pass-through
 * method called on it (`.toString()` and `.getBytes()`), with the
 * resulting bytes handed to an xmlsec sink.
 *
 * Before the receiver-taint rule, the `keyData.toString()` call had
 * zero positional arguments, so the temp synthesised by the IR lowerer
 * stayed untainted and the chain `.getBytes()` -> `signature.sign(...)`
 * never reached the `*.sign(*)` sink. With the rule the receiver's
 * taint flows through each pass-through hop and fires the sink.
 *
 * Expected: one `deserialization` flow.
 */
@RestController
public class IngestController {
    private final XMLSignature signature;

    public IngestController(XMLSignature signature) {
        this.signature = signature;
    }

    @PostMapping("/sign-receiver-chain")
    public String sign(@RequestBody String keyData) throws Exception {
        // Two-hop receiver chain: `keyData.toString().getBytes()`.
        // Both hops are 0-arg pass-throughs; both should keep taint.
        byte[] bytes = keyData.toString().getBytes();
        signature.sign(bytes);
        return "signed";
    }
}
