package com.example.JWT_Authentication.controller;

import com.example.JWT_Authentication.dto.JwtResponse;
import com.example.JWT_Authentication.dto.LoginRequest;
import com.example.JWT_Authentication.dto.RefreshTokenRequest;
import com.example.JWT_Authentication.dto.SignupRequest;
import com.example.JWT_Authentication.exception.TokenRefreshException;
import com.example.JWT_Authentication.model.User;
import com.example.JWT_Authentication.security.RefreshTokenService;
import com.example.JWT_Authentication.security.UserDetailsImpl;
import com.example.JWT_Authentication.service.UserService;
import com.example.JWT_Authentication.util.JwtUtils;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.*;
import org.springframework.security.authentication.*;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

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

        User saved = userService.save(new User(null, req.getUsername(), req.getEmail(), req.getPassword()));
        return ResponseEntity.ok("User registered with id: " + saved.getId());
    }

    @PostMapping("/signin")
    public ResponseEntity<JwtResponse> signin(@Valid @RequestBody LoginRequest login) {
        Authentication auth = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(login.getUsername(), login.getPassword()));
        SecurityContextHolder.getContext().setAuthentication(auth);
        UserDetailsImpl principal = (UserDetailsImpl) auth.getPrincipal();

        String jwt = jwtUtils.generateTokenFromUsername(principal.getUsername());
        var refresh = refreshTokenService.createRefreshToken(principal.getId());

        ResponseCookie jwtCookie = jwtUtils.generateJwtCookie(jwt);
        ResponseCookie refreshCookie = refreshTokenService.generateRefreshTokenCookie(refresh.getToken());

        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, jwtCookie.toString())
                .header(HttpHeaders.SET_COOKIE, refreshCookie.toString())
                .body(new JwtResponse(jwt, refresh.getToken(), principal.getId(), principal.getUsername(), principal.getEmail()));
    }

    @PostMapping("/refreshtoken")
    public ResponseEntity<JwtResponse> refresh(@CookieValue(name="refreshToken", required=false) String refreshTokenCookie,
                                               @RequestBody(required=false) RefreshTokenRequest body) {
        String reqToken = (body != null && body.getRefreshToken()!=null) ? body.getRefreshToken() : refreshTokenCookie;
        return refreshTokenService.findByToken(reqToken)
                .map(refreshTokenService::verifyExpiration)
                .map(rt -> {
                    var user = rt.getUser();
                    String newJwt = jwtUtils.generateTokenFromUsername(user.getUsername());
                    var newRt = refreshTokenService.createRefreshToken(user.getId());
                    ResponseCookie jwtCookie = jwtUtils.generateJwtCookie(newJwt);
                    ResponseCookie refreshCookie = refreshTokenService.generateRefreshTokenCookie(newRt.getToken());
                    return ResponseEntity.ok()
                            .header(HttpHeaders.SET_COOKIE, jwtCookie.toString())
                            .header(HttpHeaders.SET_COOKIE, refreshCookie.toString())
                            .body(new JwtResponse(newJwt, newRt.getToken(), user.getId(), user.getUsername(), user.getEmail()));
                })
                .orElseThrow(() -> new TokenRefreshException(reqToken, "Refresh token not found"));
    }

    @PostMapping("/signout")
    public ResponseEntity<String> signout() {
        var auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth != null && auth.getPrincipal() instanceof UserDetailsImpl udi) {
            refreshTokenService.deleteByUserId(udi.getId());
        }
        return ResponseEntity.ok("Signed out");
    }
}
