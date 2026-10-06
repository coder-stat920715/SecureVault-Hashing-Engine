package com.vault.hashing;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.servlet.UserDetailsServiceAutoConfiguration;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;

/**
 * Entry point of the SecureVault Hashing Engine.
 *
 * <p>The in-memory default user created by {@link UserDetailsServiceAutoConfiguration} is excluded:
 * authentication is performed by our own JWT flow against hashed credentials in the database.
 */
@SpringBootApplication(exclude = UserDetailsServiceAutoConfiguration.class)
@ConfigurationPropertiesScan
public class SecureVaultApplication {

    public static void main(String[] args) {
        SpringApplication.run(SecureVaultApplication.class, args);
    }
}
