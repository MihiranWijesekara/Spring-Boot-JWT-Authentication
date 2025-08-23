package com.example.JWT_Authentication.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/test")
public class TestController {

    @GetMapping("/public")
    public String publicEndpoint() {
        return "hello public";
    }

    @GetMapping("/private")
    @PreAuthorize("hasRole('USER')")
    public String privateEndpoint() {
        return "hello private";
    }

}

