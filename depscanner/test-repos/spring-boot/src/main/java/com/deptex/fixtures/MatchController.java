package com.deptex.fixtures;

import org.springframework.expression.ExpressionParser;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.regex.Pattern;

@RestController
@RequestMapping("/match")
public class MatchController {

    private final ExpressionParser parser = new SpelExpressionParser();

    @GetMapping("/regex")
    public String regex(@RequestParam String pattern) {
        // REACHABLE: redos — user-supplied regex compiled (catastrophic backtracking).
        Pattern compiled = Pattern.compile(pattern);
        return "ok";
    }

    @GetMapping("/eval")
    public String eval(@RequestParam String expr) {
        // REACHABLE: code_injection — tainted SpEL expression parsed and evaluable.
        parser.parseExpression(expr);
        return "ok";
    }
}
