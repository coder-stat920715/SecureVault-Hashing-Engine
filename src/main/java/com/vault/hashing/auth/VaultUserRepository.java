package com.vault.hashing.auth;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface VaultUserRepository extends JpaRepository<VaultUser, Long> {

    Optional<VaultUser> findByUsername(String username);

    boolean existsByUsername(String username);
}
