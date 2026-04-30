package com.example;

public class ShellService {
    public String run(String input) {
        try {
            Runtime rt = Runtime.getRuntime();
            // Sink: untrusted input passed straight to shell.
            Process proc = rt.exec(input);
            return "ran: " + input;
        } catch (Exception e) {
            return "error";
        }
    }
}
