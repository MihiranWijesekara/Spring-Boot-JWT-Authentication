package com.example.JWT_Authentication.controller;

import com.example.JWT_Authentication.dto.LoginRequest;
import com.example.JWT_Authentication.dto.SignupRequest;
import com.example.JWT_Authentication.model.User;
import com.example.JWT_Authentication.security.RefreshTokenService;
import com.example.JWT_Authentication.security.UserDetailsImpl;
import com.example.JWT_Authentication.service.UserService;
import com.example.JWT_Authentication.util.JwtUtils;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.*;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

@CrossOrigin(origins="*", maxAge=3600)
@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthenticationManager authenticationManager;
    private final UserService userService;
    private final JwtUtils jwtUtils;
    private final RefreshTokenService refreshTokenService;

    @PostMapping("/signup")
    public ResponseEntity<?> register(@Valid @RequestBody SignupRequest req) {
        if (userService.existsByUsername(req.getUsername())) {
            return ResponseEntity.badRequest().body("Error: Username is already taken!");
        }
        if (userService.existsByEmail(req.getEmail())) {
            return ResponseEntity.badRequest().body("Error: Email is already in use!");
        }
        if (req.getPassword() == null || req.getPassword().isBlank()) {
            return ResponseEntity.badRequest().body("Error: Password is required!");
        }

        User user = new User();
        user.setUsername(req.getUsername());
        user.setEmail(req.getEmail());
        user.setPassword(req.getPassword());
        user.setRoles(req.getRoles());

        User saved = userService.save(user);
        return ResponseEntity.ok("User registered with id: " + saved.getId());
    }

    @PostMapping("/signin")
    public ResponseEntity<?> signin(@Valid @RequestBody LoginRequest login) {
        Authentication auth = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(login.getUsername(), login.getPassword()));
        SecurityContextHolder.getContext().setAuthentication(auth);
        UserDetailsImpl principal = (UserDetailsImpl) auth.getPrincipal();

        String jwt = jwtUtils.generateTokenFromUsername(principal.getUsername());
        var refreshPair = refreshTokenService.createRefreshToken(principal.getId());

        ResponseCookie jwtCookie = jwtUtils.generateJwtCookie(jwt);
        ResponseCookie refreshCookie = refreshPair.cookie();

        // Include roles in response
        Set<String> roles = principal.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toSet());

        Map<String, Object> body = Map.of(
                "id", principal.getId(),
                "username", principal.getUsername(),
                "email", principal.getEmail(),
                "roles", roles
        );

        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, jwtCookie.toString())
                .header(HttpHeaders.SET_COOKIE, refreshCookie.toString())
                .body(body);
    }

    @PostMapping("/refreshtoken")
    public ResponseEntity<?> refresh(@CookieValue(name="refreshToken", required=false) String refreshCookieVal) {
        var oldToken = refreshTokenService.verifyCookieAndLoad(refreshCookieVal);

        // rotate refresh + issue new access
        var rotated = refreshTokenService.rotate(oldToken);
        String newJwt = jwtUtils.generateTokenFromUsername(oldToken.getUser().getUsername());

        ResponseCookie jwtCookie = jwtUtils.generateJwtCookie(newJwt);

        Set<String> roles = oldToken.getUser().getRoles().stream()
                .map(Enum::name)
                .collect(Collectors.toSet());

        Map<String, Object> body = Map.of(
                "id", oldToken.getUser().getId(),
                "username", oldToken.getUser().getUsername(),
                "email", oldToken.getUser().getEmail(),
                "roles", roles
        );

        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, jwtCookie.toString())
                .header(HttpHeaders.SET_COOKIE, rotated.cookie().toString())
                .body(body);
    }

    @PostMapping("/signout")
    public ResponseEntity<String> signout() {
        var auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth != null && auth.getPrincipal() instanceof UserDetailsImpl udi) {
            try {
                int deletedCount = refreshTokenService.deleteByUserId(udi.getId());
                System.out.println("Deleted " + deletedCount + " refresh tokens for user: " + udi.getId());
            } catch (Exception e) {
                System.err.println("Error deleting refresh tokens: " + e.getMessage());
                e.printStackTrace();
            }
        }
        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, jwtUtils.getCleanJwtCookie().toString())
                .header(HttpHeaders.SET_COOKIE, refreshTokenService.getCleanRefreshTokenCookie().toString())
                .body("Signed out");
    }
}