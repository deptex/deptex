package com.example;

public class ShellService {
    public String runFixed(String which) {
        try {
            Runtime rt = Runtime.getRuntime();
            // Safe: hardcoded constant — no taint flows here.
            Process proc = rt.exec("echo hello");
            return "ran fixed";
        } catch (Exception e) {
            return "error";
        }
    }
}
