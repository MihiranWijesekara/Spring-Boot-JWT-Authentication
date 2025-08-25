package com.example.JWT_Authentication.model;

import jakarta.persistence.*;
import lombok.*;
import java.time.Instant;

@Getter @Setter
@NoArgsConstructor @AllArgsConstructor
@Entity
@Table(name = "refresh_token")
public class RefreshToken {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    // CHANGE FROM @OneToOne TO @ManyToOne
    @ManyToOne
    @JoinColumn(name = "user_id", referencedColumnName = "id") // No unique constraint!
    private User user;

    @Column(nullable = false, unique = true, length = 36)
    private String tokenId;

    @Column(nullable = false, length = 64)
    private String tokenHash;

    @Column(nullable = false)
    private Instant expiryDate;

    @Column(nullable = false)
    private boolean revoked = false;

    private String replacedByTokenId;
}