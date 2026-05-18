package com.example.service;

public class AuditService {
    public void record(String payload) {
        System.out.println("ingest: " + payload.length() + " bytes");
    }
}
