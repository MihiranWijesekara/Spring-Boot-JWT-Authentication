package com.example.JWT_Authentication.model;

import jakarta.persistence.*;
import lombok.*;

import java.time.Instant;

@Getter @Setter
@NoArgsConstructor @AllArgsConstructor
@Entity @Table(name = "refresh_token",
        indexes = {@Index(name = "idx_ref_token_token_id", columnList = "tokenId", unique = true)})
public class RefreshToken {

    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    /** Who owns this token */
    @OneToOne
    @JoinColumn(name = "user_id", referencedColumnName = "id")
    private User user;

    /** Public identifier we can look up quickly (kept in cookie). */
    @Column(nullable = false, unique = true, length = 36)
    private String tokenId; // UUID string

    /** Hash (SHA-256 Base64) of the raw secret part. Never store the raw token. */
    @Column(nullable = false, length = 64) // 44 for Base64, 64 leaves headroom
    private String tokenHash;

    @Column(nullable = false)
    private Instant expiryDate;

    @Column(nullable = false)
    private boolean revoked = false;

    /** If rotated, track the replacement's tokenId (optional). */
    private String replacedByTokenId;
}
