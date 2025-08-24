package com.example.JWT_Authentication.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/user")
@PreAuthorize("hasAnyRole('USER', 'ADMIN')")
public class UserController {

    @GetMapping("/profile")
    public String userProfile() {
        return "User Profile - Accessible to both USER and ADMIN";
    }

    @GetMapping("/dashboard")
    public String userDashboard() {
        return "User Dashboard - Accessible to both USER and ADMIN";
    }
}