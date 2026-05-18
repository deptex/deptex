package com.example;

import org.apache.xml.security.signature.XMLSignature;

public class XmlSigner {
    private final XMLSignature signature;

    public XmlSigner(XMLSignature signature) {
        this.signature = signature;
    }

    public String sign(byte[] bytes) {
        try {
            // Even though XMLSignature.sign(...) is a modeled sink, no
            // tainted source flows here in the safe fixture: the caller
            // passes a hard-coded literal.
            signature.sign(bytes);
            return "signed";
        } catch (Exception e) {
            return "error";
        }
    }
}
