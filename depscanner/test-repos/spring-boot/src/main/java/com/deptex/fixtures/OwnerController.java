package com.deptex.fixtures;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/owners")
public class OwnerController {

    private final JdbcTemplate jdbc;

    public OwnerController(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    @GetMapping("/find")
    public List<Map<String, Object>> findOwners(@RequestParam String name) {
        // REACHABLE: user input concatenated into SQL string -> SQLi.
        String sql = "SELECT * FROM owners WHERE last_name LIKE '%" + name + "%'";
        return jdbc.queryForList(sql);
    }

    @GetMapping("/{id}")
    public Map<String, Object> findById(@RequestParam("id") long id) {
        // UNREACHABLE: parameterised query.
        return jdbc.queryForMap("SELECT * FROM owners WHERE id = ?", id);
    }
}
