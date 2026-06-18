package com.deptex.fixtures;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/process")
public class ProcessController {

    @GetMapping("/run")
    public String run(@RequestParam String cmd) throws Exception {
        // REACHABLE: command_injection — user input passed straight to a shell.
        Runtime runtime = Runtime.getRuntime();
        runtime.exec(cmd);
        return "ok";
    }

    @PostMapping("/spawn")
    public String spawn(@RequestParam String binary) throws Exception {
        // REACHABLE: command_injection — tainted argument into ProcessBuilder.
        ProcessBuilder builder = new ProcessBuilder(binary);
        builder.start();
        return "ok";
    }
}
