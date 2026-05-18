package com.example.service;

public class AuditService {
    public void record(String payload) {
        // Best-effort audit hook — does not sanitize.
        System.out.println("ingest: " + payload.length() + " bytes");
    }
}
