package com.example.JWT_Authentication.service.IMPL;



import com.example.JWT_Authentication.model.User;
import com.example.JWT_Authentication.repository.UserRepository;
import com.example.JWT_Authentication.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {
    private final UserRepository repo;
    private final PasswordEncoder encoder;

    @Override public User save(User user) { user.setPassword(encoder.encode(user.getPassword())); return repo.save(user); }
    @Override public boolean existsByUsername(String u) { return repo.existsByUsername(u); }
    @Override public boolean existsByEmail(String e) { return repo.existsByEmail(e); }
}

