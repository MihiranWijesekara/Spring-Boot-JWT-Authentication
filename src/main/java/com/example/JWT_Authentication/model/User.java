// src/main/java/com/example/JWT_Authentication/model/User.java
package com.example.JWT_Authentication.model;

import jakarta.persistence.*;
import lombok.*;

@Getter @Setter
@NoArgsConstructor @AllArgsConstructor
@Entity @Table(name = "users")
public class User {
    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(unique = true, nullable=false)
    private String username;

    @Column(unique = true, nullable=false)
    private String email;

    @Column(nullable=false)
    private String password;
}
