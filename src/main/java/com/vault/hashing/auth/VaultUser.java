package com.vault.hashing.auth;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.Instant;
import java.util.Arrays;
import java.util.List;

/** Registered user. Only the salted, slow password hash is stored, never the password itself. */
@Entity
@Table(name = "vault_users",
        uniqueConstraints = @UniqueConstraint(name = "uk_vault_users_username", columnNames = "username"))
@Getter
@Setter
@NoArgsConstructor
public class VaultUser {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "username", nullable = false, length = 50)
    private String username;

    /** Prefixed encoded hash, e.g. {@code {argon2}$argon2id$v=19$m=19456,t=2,p=1$<salt>$<hash>}. */
    @Column(name = "password_hash", nullable = false, length = 255)
    private String passwordHash;

    /** Comma separated authorities, e.g. {@code ROLE_USER,ROLE_ADMIN}. */
    @Column(name = "roles", nullable = false, length = 255)
    private String roles = "ROLE_USER";

    @Column(name = "enabled", nullable = false)
    private boolean enabled = true;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt = Instant.now();

    public List<String> roleList() {
        return Arrays.stream(roles.split(",")).map(String::trim).filter(s -> !s.isEmpty()).toList();
    }
}
