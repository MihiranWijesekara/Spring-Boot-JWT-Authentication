package com.example.JWT_Authentication.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/admin")
@PreAuthorize("hasRole('ADMIN')")
public class AdminController {

    @GetMapping("/dashboard")
    public String adminDashboard() {
        return "Admin Dashboard - Only accessible to ADMIN users";
    }

    @GetMapping("/users")
    public String manageUsers() {
        return "User Management - Admin only";
    }
}

