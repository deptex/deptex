package com.example;

import java.nio.file.Files;
import java.nio.file.Paths;

public class FileService {
    public byte[] read(String name) {
        try {
            return Files.readAllBytes(Paths.get(name));
        } catch (Exception e) {
            return new byte[0];
        }
    }
}
