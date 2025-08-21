package com.example.JWT_Authentication.security;

import com.example.JWT_Authentication.exception.TokenRefreshException;
import com.example.JWT_Authentication.model.RefreshToken;
import com.example.JWT_Authentication.repository.RefreshTokenRepository;
import com.example.JWT_Authentication.repository.UserRepository;
import com.example.JWT_Authentication.util.JwtUtils;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class RefreshTokenService {

    private final RefreshTokenRepository refreshTokenRepository;
    private final UserRepository userRepository;
    private final JwtUtils jwtUtils; // we’ll read Duration values via helpers

    public Optional<RefreshToken> findByToken(String token) {
        return refreshTokenRepository.findByToken(token);
    }

    public RefreshToken createRefreshToken(Long userId) {
        var token = new RefreshToken();
        token.setUser(userRepository.findById(userId).orElseThrow());
        token.setExpiryDate(Instant.now().plusMillis(jwtUtils.getRefreshTtlMillis()));
        token.setToken(UUID.randomUUID().toString());
        return refreshTokenRepository.save(token);
    }

    public RefreshToken verifyExpiration(RefreshToken token) {
        if (token.getExpiryDate().isBefore(Instant.now())) {
            refreshTokenRepository.delete(token);
            throw new TokenRefreshException(token.getToken(), "Refresh token expired. Sign in again.");
        }
        return token;
    }

    @Transactional
    public int deleteByUserId(Long userId) {
        return refreshTokenRepository.deleteByUser(userRepository.findById(userId).orElseThrow());
    }

    // ---------- Cookie helpers for refresh token ----------

    /** Cookie path is the refresh endpoint to limit exposure. */
    public ResponseCookie generateRefreshTokenCookie(String token) {
        return ResponseCookie.from("refreshToken", token)
                .httpOnly(true)
                .secure(true)
                .path("/api/auth/refreshtoken")
                .sameSite("Strict")
                .maxAge((int) jwtUtils.getRefreshTtlSeconds())
                .build();
    }

    public ResponseCookie getCleanRefreshTokenCookie() {
        return ResponseCookie.from("refreshToken", "")
                .httpOnly(true)
                .secure(true)
                .path("/api/auth/refreshtoken")
                .sameSite("Strict")
                .maxAge(0)
                .build();
    }
}
