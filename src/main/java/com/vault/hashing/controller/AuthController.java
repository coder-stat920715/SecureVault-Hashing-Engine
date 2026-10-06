package com.vault.hashing.controller;

import com.vault.hashing.auth.AuthDtos.AuthResponse;
import com.vault.hashing.auth.AuthDtos.LoginRequest;
import com.vault.hashing.auth.AuthDtos.RegisterRequest;
import com.vault.hashing.auth.AuthDtos.UserResponse;
import com.vault.hashing.auth.AuthService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/** Use case 1: registration (salted Argon2/BCrypt hash) and login (HS256-signed JWT). */
@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    @PostMapping("/register")
    public ResponseEntity<UserResponse> register(@Valid @RequestBody RegisterRequest request) {
        return ResponseEntity.status(HttpStatus.CREATED).body(authService.register(request));
    }

    @PostMapping("/login")
    public AuthResponse login(@Valid @RequestBody LoginRequest request) {
        return authService.login(request);
    }
}
