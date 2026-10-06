package com.vault.hashing.auth;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

import java.time.Instant;
import java.util.List;

/** Request/response payloads of the authentication API. */
public final class AuthDtos {

    private AuthDtos() {
    }

    /** Password is capped at 72 chars because BCrypt only considers the first 72 bytes of its input. */
    public record RegisterRequest(
            @NotBlank @Size(min = 3, max = 50)
            @Pattern(regexp = "^[A-Za-z0-9._-]+$", message = "may only contain letters, digits, '.', '_' and '-'")
            String username,
            @NotBlank @Size(min = 12, max = 72) String password) {
    }

    public record LoginRequest(@NotBlank String username, @NotBlank String password) {
    }

    public record AuthResponse(String token, String tokenType, long expiresInSeconds, String username) {
    }

    public record UserResponse(Long id, String username, List<String> roles, Instant createdAt) {
    }
}
