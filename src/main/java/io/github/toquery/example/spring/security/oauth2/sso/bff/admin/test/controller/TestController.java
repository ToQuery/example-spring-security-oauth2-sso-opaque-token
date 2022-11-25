package io.github.toquery.example.spring.security.oauth2.sso.bff.admin.test.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

/**
 *
 */
@RequiredArgsConstructor
@RestController
@RequestMapping("/admin/test")
public class TestController {

    private final ObjectMapper objectMapper;

    @SneakyThrows
    @ResponseBody
    @GetMapping("/info")
    public Map<String, String> info(Authentication authentication){
        Map<String,String> map = new HashMap<String, String>();
        map.put("name", "TestController");
        map.put("authenticationClass", authentication.getClass().getName());
        map.put("authentication", objectMapper.writeValueAsString(authentication));
        return map;
    }
}
