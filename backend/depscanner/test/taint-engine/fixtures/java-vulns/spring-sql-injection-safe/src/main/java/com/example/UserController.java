package com.example;

import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

@RestController
public class UserController {
    private final UserRepository repo;

    public UserController(UserRepository repo) {
        this.repo = repo;
    }

    @GetMapping("/users")
    public String findUser(@RequestParam String id) {
        // Safe: id is coerced to integer before reaching the repo (sanitizer).
        int parsed = Integer.parseInt(id);
        return repo.findById(parsed);
    }
}
