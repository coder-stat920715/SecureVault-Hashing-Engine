package com.vault.hashing.auth;

import com.vault.hashing.auth.AuthDtos.AuthResponse;
import com.vault.hashing.auth.AuthDtos.LoginRequest;
import com.vault.hashing.auth.AuthDtos.RegisterRequest;
import com.vault.hashing.auth.AuthDtos.UserResponse;
import com.vault.hashing.common.VaultExceptions.ConflictException;
import com.vault.hashing.common.VaultExceptions.InvalidCredentialsException;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Locale;
import java.util.Optional;
import java.util.UUID;

/** Registration and login. Passwords are only ever handled as raw input and as salted slow hashes. */
@Service
public class AuthService {

    private final VaultUserRepository users;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;

    /** Hash of a throw-away password, verified against when the user is unknown (see {@link #login}). */
    private final String dummyHash;

    public AuthService(VaultUserRepository users, PasswordEncoder passwordEncoder, JwtService jwtService) {
        this.users = users;
        this.passwordEncoder = passwordEncoder;
        this.jwtService = jwtService;
        this.dummyHash = passwordEncoder.encode(UUID.randomUUID().toString());
    }

    @Transactional
    public UserResponse register(RegisterRequest request) {
        String username = normalize(request.username());
        if (users.existsByUsername(username)) {
            throw new ConflictException("Username is already taken");
        }
        VaultUser user = new VaultUser();
        user.setUsername(username);
        // A fresh random salt is generated inside encode(); work factor comes from configuration.
        user.setPasswordHash(passwordEncoder.encode(request.password()));
        try {
            user = users.saveAndFlush(user);
        } catch (DataIntegrityViolationException e) {
            throw new ConflictException("Username is already taken");
        }
        return new UserResponse(user.getId(), user.getUsername(), user.roleList(), user.getCreatedAt());
    }

    @Transactional
    public AuthResponse login(LoginRequest request) {
        String username = normalize(request.username());
        Optional<VaultUser> found = users.findByUsername(username);

        if (found.isEmpty()) {
            // Spend the same CPU time as a real verification so response time does not reveal
            // whether the username exists (user-enumeration timing side channel).
            passwordEncoder.matches(request.password(), dummyHash);
            throw new InvalidCredentialsException();
        }

        VaultUser user = found.get();
        boolean passwordOk = passwordEncoder.matches(request.password(), user.getPasswordHash());
        if (!passwordOk || !user.isEnabled()) {
            throw new InvalidCredentialsException();
        }

        // Transparent hash upgrade when the configured algorithm/work factor has changed.
        if (passwordEncoder.upgradeEncoding(user.getPasswordHash())) {
            user.setPasswordHash(passwordEncoder.encode(request.password()));
        }

        String token = jwtService.generateToken(user.getUsername(), user.roleList());
        return new AuthResponse(token, "Bearer", jwtService.getTtl().toSeconds(), user.getUsername());
    }

    private static String normalize(String username) {
        return username.trim().toLowerCase(Locale.ROOT);
    }
}
