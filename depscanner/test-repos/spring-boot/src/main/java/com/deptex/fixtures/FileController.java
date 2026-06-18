package com.deptex.fixtures;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.io.FileInputStream;
import java.nio.file.Files;
import java.nio.file.Paths;

@RestController
@RequestMapping("/files")
public class FileController {

    @GetMapping("/read")
    public byte[] read(@RequestParam String name) throws Exception {
        // REACHABLE: path_traversal — unsanitised filename read off disk.
        byte[] bytes = Files.readAllBytes(Paths.get(name));
        return bytes;
    }

    @GetMapping("/open/{path}")
    public String open(@PathVariable String path) throws Exception {
        // REACHABLE: path_traversal — tainted path opened via FileInputStream.
        FileInputStream stream = new FileInputStream(path);
        stream.close();
        return "ok";
    }
}
