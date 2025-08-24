package com.example.JWT_Authentication.service.IMPL;

import com.example.JWT_Authentication.model.User;
import com.example.JWT_Authentication.repository.UserRepository;
import com.example.JWT_Authentication.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.HashSet;

@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {
    private final UserRepository repo;
    private final PasswordEncoder encoder;

    @Override
    public User save(User user) {
        if (user.getRoles() == null || user.getRoles().isEmpty()) {
            user.setRoles(new HashSet<>());
            user.getRoles().add(User.Role.ROLE_USER);
        }
        user.setPassword(encoder.encode(user.getPassword()));
        return repo.save(user);
    }

    @Override
    public boolean existsByUsername(String u) {
        return repo.existsByUsername(u);
    }

    @Override
    public boolean existsByEmail(String e) {
        return repo.existsByEmail(e);
    }

    @Override
    public User findById(Long id) {
        return repo.findById(id).orElse(null);
    }
}