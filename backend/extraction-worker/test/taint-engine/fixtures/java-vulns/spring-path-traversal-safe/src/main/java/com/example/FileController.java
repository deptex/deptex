package com.example;

import java.nio.file.Paths;

import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

@RestController
public class FileController {
    private final FileService service;

    public FileController(FileService service) {
        this.service = service;
    }

    @GetMapping("/download")
    public byte[] download(@RequestParam String name) {
        // Strip directory components — only the final filename reaches the service.
        String safe = Paths.get(name).getFileName().toString();
        return service.read(safe);
    }
}
