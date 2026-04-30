package com.example;

import java.sql.Connection;
import java.sql.Statement;

public class UserRepository {
    private final Connection conn;

    public UserRepository(Connection conn) {
        this.conn = conn;
    }

    public String findById(String id) {
        try {
            Statement stmt = conn.createStatement();
            // Sink: id is concatenated directly into SQL string.
            String sql = "SELECT * FROM users WHERE id = '" + id + "'";
            stmt.executeQuery(sql);
            return sql;
        } catch (Exception e) {
            return null;
        }
    }
}
