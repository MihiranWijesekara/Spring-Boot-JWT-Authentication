package com.example.JWT_Authentication.util;

import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Date;

@Slf4j
@Component
public class JwtUtils {

    @Value("${jwt.secret}")
    private String jwtSecret;

    // Human-readable durations from properties, e.g. 15m, 24h
    @Value("${jwt.expiration}")
    private Duration jwtExpiration;

    @Value("${jwt.refreshExpiration}")
    private Duration refreshExpiration;

    private SecretKey signingKey;

    @PostConstruct
    void init() {
        // Build the HMAC key once
        this.signingKey = Keys.hmacShaKeyFor(jwtSecret.getBytes(StandardCharsets.UTF_8));
    }

    /** Create a short-lived access token for the given username. */
    public String generateTokenFromUsername(String username) {
        final long now = System.currentTimeMillis();
        return Jwts.builder()
                .setSubject(username)
                .setIssuedAt(new Date(now))
                .setExpiration(new Date(now + jwtExpiration.toMillis()))
                .signWith(signingKey, SignatureAlgorithm.HS256)
                .compact();
    }

    /** Extract username (subject) from JWT. */
    public String getUserNameFromJwtToken(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(signingKey)
                .build()
                .parseClaimsJws(token)
                .getBody()
                .getSubject();
    }

    /** Validate signature/expiry of the JWT. */
    public boolean validateJwtToken(String token) {
        try {
            Jwts.parserBuilder()
                    .setSigningKey(signingKey)
                    .build()
                    .parseClaimsJws(token);
            return true;
        } catch (JwtException | IllegalArgumentException e) {
            log.error("JWT validation error: {}", e.getMessage());
            return false;
        }
    }

    // ---------- Cookie helpers ----------

    /** Access-token cookie (JWT) scoped to site root. */
    public ResponseCookie generateJwtCookie(String token) {
        return ResponseCookie.from("jwt", token)
                .httpOnly(true)
                .secure(true)
                .path("/")              // send to all endpoints
                .sameSite("Strict")
                .maxAge((int) jwtExpiration.toSeconds())
                .build();
    }

    public ResponseCookie getCleanJwtCookie() {
        return ResponseCookie.from("jwt", "")
                .httpOnly(true)
                .secure(true)
                .path("/")
                .sameSite("Strict")
                .maxAge(0)
                .build();
    }

    /** For other beans that need the refresh TTL (seconds). */
    public long getRefreshTtlSeconds() {
        return refreshExpiration.toSeconds();
    }

    /** For other beans that need the refresh TTL (millis). */
    public long getRefreshTtlMillis() {
        return refreshExpiration.toMillis();
    }
}
