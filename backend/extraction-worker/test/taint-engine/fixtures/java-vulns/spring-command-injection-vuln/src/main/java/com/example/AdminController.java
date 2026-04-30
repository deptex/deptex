package com.example;

import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

@RestController
public class AdminController {
    private final ShellService shell;

    public AdminController(ShellService shell) {
        this.shell = shell;
    }

    @PostMapping("/admin/run")
    public String runCommand(@RequestParam String cmd) {
        // Vulnerable: cmd flows directly into Runtime.exec via the service.
        return shell.run(cmd);
    }
}
