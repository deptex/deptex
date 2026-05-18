package com.example;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

/**
 * CVE-2023-44483-shaped vulnerable fixture ("XML Signature wrapping" in
 * Apache Santuario / xmlsec).
 *
 * Spring REST controller takes attacker-controlled XML via @RequestBody and
 * hands the bytes to XmlSigner.sign(...), which calls
 * org.apache.xml.security.signature.XMLSignature.sign on them. xmlsec
 * &lt; 3.0.3 is vulnerable to a signature-wrapping bypass where the signed
 * manifest references a different subtree than the one rendered to the
 * verifier.
 *
 * vuln_class = deserialization (closest fit in the engine enum — the
 * library consumes attacker-shaped serialised XML, same regime as
 * jackson-databind polymorphic deser).
 */
@RestController
public class IngestController {
    private final XmlSigner signer;

    public IngestController(XmlSigner signer) {
        this.signer = signer;
    }

    @PostMapping("/sign")
    public String sign(@RequestBody byte[] body) {
        // Source: @RequestBody byte[] — tainted by Spring spec.
        // Cross-file: signer.sign() reaches the actual sink call site.
        return signer.sign(body);
    }
}
