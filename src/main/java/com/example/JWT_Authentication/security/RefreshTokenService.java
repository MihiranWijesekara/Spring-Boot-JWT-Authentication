package com.example.JWT_Authentication.security;

import com.example.JWT_Authentication.exception.TokenRefreshException;
import com.example.JWT_Authentication.model.RefreshToken;
import com.example.JWT_Authentication.repository.RefreshTokenRepository;
import com.example.JWT_Authentication.repository.UserRepository;
import com.example.JWT_Authentication.util.HashingUtils;
import com.example.JWT_Authentication.util.JwtUtils;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.Optional;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class RefreshTokenService {

    private final RefreshTokenRepository refreshTokenRepository;
    private final UserRepository userRepository;
    private final JwtUtils jwtUtils;

    private static final SecureRandom RNG = new SecureRandom();

    /** Create a hashed refresh token and return the cookie to set. */
    public RefreshCookiePair createRefreshToken(Long userId) {
        var user = userRepository.findById(userId).orElseThrow();

        // Generate high-entropy raw secret (Base64URL, no padding)
        byte[] buf = new byte[32]; // 256-bit
        RNG.nextBytes(buf);
        String rawSecret = Base64.getUrlEncoder().withoutPadding().encodeToString(buf);

        String tokenId = UUID.randomUUID().toString();
        String hash = HashingUtils.sha256Base64(rawSecret);

        var rt = new RefreshToken();
        rt.setUser(user);
        rt.setTokenId(tokenId);
        rt.setTokenHash(hash);
        rt.setExpiryDate(Instant.now().plusMillis(jwtUtils.getRefreshTtlMillis()));
        rt.setRevoked(false);
        refreshTokenRepository.save(rt);

        // cookie value carries public id + raw secret; server stores only hash
        String cookieValue = tokenId + "." + rawSecret;
        ResponseCookie cookie = ResponseCookie.from("refreshToken", cookieValue)
                .httpOnly(true).secure(true)
                .path("/api/auth/refreshtoken")
                .sameSite("Strict")
                .maxAge((int) jwtUtils.getRefreshTtlSeconds())
                .build();

        return new RefreshCookiePair(rt, cookie);
    }

    /** Verify incoming cookie, return the DB token if valid (not expired/revoked). */
    public RefreshToken verifyCookieAndLoad(String cookieValue) {
        if (cookieValue == null || !cookieValue.contains(".")) {
            throw new TokenRefreshException("<none>", "Invalid refresh token format");
        }
        String tokenId = cookieValue.substring(0, cookieValue.indexOf('.'));
        String rawSecret = cookieValue.substring(cookieValue.indexOf('.') + 1);

        RefreshToken token = refreshTokenRepository.findByTokenId(tokenId)
                .orElseThrow(() -> new TokenRefreshException(tokenId, "Refresh token not found"));

        if (token.isRevoked()) {
            throw new TokenRefreshException(tokenId, "Refresh token revoked");
        }
        if (token.getExpiryDate().isBefore(Instant.now())) {
            token.setRevoked(true);
            refreshTokenRepository.save(token);
            throw new TokenRefreshException(tokenId, "Refresh token expired");
        }

        String presentedHash = HashingUtils.sha256Base64(rawSecret);
        if (!HashingUtils.constantTimeEquals(token.getTokenHash(), presentedHash)) {
            throw new TokenRefreshException(tokenId, "Refresh token hash mismatch");
        }
        return token;
    }

    /** Revoke and rotate the old refresh token, returning a new cookie. */
    @Transactional
    public RefreshCookiePair rotate(RefreshToken oldToken) {
        oldToken.setRevoked(true);

        // new token for same user
        RefreshCookiePair pair = createRefreshToken(oldToken.getUser().getId());
        oldToken.setReplacedByTokenId(pair.entity().getTokenId());

        refreshTokenRepository.save(oldToken);
        return pair;
    }

    @Transactional
    public int deleteByUserId(Long userId) {
        return refreshTokenRepository.deleteByUser(userRepository.findById(userId).orElseThrow());
    }

    public ResponseCookie getCleanRefreshTokenCookie() {
        return ResponseCookie.from("refreshToken", "")
                .httpOnly(true).secure(true)
                .path("/api/auth/refreshtoken")
                .sameSite("Strict").maxAge(0).build();
    }

    // Simple record to return both DB entity and cookie
    public record RefreshCookiePair(RefreshToken entity, ResponseCookie cookie) {}
}
