package com.example;

import java.sql.Connection;
import java.sql.PreparedStatement;

public class UserRepository {
    private final Connection conn;

    public UserRepository(Connection conn) {
        this.conn = conn;
    }

    public String findById(int id) {
        try {
            // Safe: parameterized query, id is bound via setInt (sanitizer).
            PreparedStatement stmt = conn.prepareStatement("SELECT * FROM users WHERE id = ?");
            stmt.setInt(1, id);
            stmt.executeQuery();
            return null;
        } catch (Exception e) {
            return null;
        }
    }
}
