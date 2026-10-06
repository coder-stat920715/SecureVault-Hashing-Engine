package com.vault.hashing.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.DelegatingPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Map;

@Configuration
public class PasswordEncoderConfig {

    /**
     * Password hashing (use case 1).
     *
     * <p><b>Why Argon2id / BCrypt and not SHA-256?</b> General-purpose hashes are designed to be fast, which
     * lets an attacker test billions of guesses per second on a GPU. Password hashes are deliberately slow and
     * tunable: BCrypt via its cost factor (2^n rounds), Argon2id via memory, iterations and parallelism, which
     * also makes GPU/ASIC attacks expensive. Both generate a unique random salt per password and embed it in the
     * encoded string, so identical passwords yield different hashes and rainbow tables are useless.
     *
     * <p>The {@link DelegatingPasswordEncoder} prefixes hashes with {@code {argon2}} / {@code {bcrypt}}, so the
     * configured algorithm or work factor can be changed later while old hashes continue to verify.
     */
    @Bean
    public PasswordEncoder passwordEncoder(VaultProperties properties) {
        VaultProperties.Password cfg = properties.getPassword();

        PasswordEncoder argon2 = new Argon2PasswordEncoder(
                cfg.getSaltLength(), cfg.getHashLength(), cfg.getParallelism(), cfg.getMemoryKib(), cfg.getIterations());
        PasswordEncoder bcrypt = new BCryptPasswordEncoder(cfg.getBcryptStrength());

        String idForEncode = cfg.getAlgorithm() == VaultProperties.Password.Algorithm.ARGON2 ? "argon2" : "bcrypt";
        return new DelegatingPasswordEncoder(idForEncode, Map.of("argon2", argon2, "bcrypt", bcrypt));
    }
}
