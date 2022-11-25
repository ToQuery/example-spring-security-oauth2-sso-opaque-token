package io.github.toquery.example.spring.security.oauth2.sso.bff.admin.index.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

/**
 *
 */
@RequiredArgsConstructor
@RestController
public class IndexController {

    @SneakyThrows
    @ResponseBody
    @GetMapping(value = {"/", "/index"})
    public Map<String, Object> index() {
        Map<String, Object> map = new HashMap<>();
        map.put("name", "IndexController.index");
        return map;
    }

    @SneakyThrows
    @ResponseBody
    @GetMapping(value = "info")
    public Map<String, Object> info(Authentication authentication) {
        Map<String, Object> map = new HashMap<>();

        map.put("name", "TestController");
        map.put("authenticationClass", authentication.getClass().getName());
        map.put("authentication", authentication);

        return map;
    }
}
