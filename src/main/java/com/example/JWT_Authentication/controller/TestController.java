package com.example.JWT_Authentication.controller;

import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/test")
public class TestController {

    @GetMapping("/public")
    public String publicEndpoint() {
        return "hello public";
    }

    @GetMapping("/private")
    public String privateEndpoint() {
        return "hello private";
    }
}

