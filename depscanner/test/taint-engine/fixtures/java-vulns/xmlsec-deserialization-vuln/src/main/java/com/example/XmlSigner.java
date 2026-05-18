package com.example;

import org.apache.xml.security.signature.XMLSignature;

public class XmlSigner {
    private final XMLSignature signature;

    public XmlSigner(XMLSignature signature) {
        this.signature = signature;
    }

    public String sign(byte[] bytes) {
        try {
            // Sink: tainted XML bytes flow into XMLSignature.sign(...). The
            // xmlsec.yaml spec models this with `*.sign(*)` →
            // vuln_class=deserialization, argument_indices=[] (any tainted
            // arg fires). CVE-2023-44483 wraps the signed manifest around a
            // different rendered subtree.
            signature.sign(bytes);
            return "signed";
        } catch (Exception e) {
            return "error";
        }
    }
}
