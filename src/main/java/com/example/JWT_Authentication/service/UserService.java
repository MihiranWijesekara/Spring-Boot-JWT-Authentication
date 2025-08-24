package com.example.JWT_Authentication.service;


import com.example.JWT_Authentication.model.User;

public interface UserService {
    User save(User user);
    boolean existsByUsername(String u);
    boolean existsByEmail(String e);

    User findById(Long id);
}
