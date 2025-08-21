package com.example.JWT_Authentication.repository;

import com.example.JWT_Authentication.model.RefreshToken;
import com.example.JWT_Authentication.model.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {
    Optional<RefreshToken> findByToken(String token);
    int deleteByUser(User user);
}
