package com.deptex.fixtures;

import javax.servlet.http.HttpServletResponse;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/redirect")
public class RedirectController {

    @GetMapping("/go")
    public void go(@RequestParam String url, HttpServletResponse response) throws Exception {
        // REACHABLE: open_redirect — user-controlled redirect target.
        String destination = url;
        response.sendRedirect(destination);
    }

    @GetMapping("/render")
    public void render(@RequestParam String html, HttpServletResponse response) throws Exception {
        // REACHABLE: xss — tainted markup written to the raw response writer.
        java.io.PrintWriter writer = response.getWriter();
        writer.write(html);
    }
}
