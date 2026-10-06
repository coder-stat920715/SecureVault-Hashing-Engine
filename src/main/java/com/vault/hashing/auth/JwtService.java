package com.vault.hashing.auth;

import com.vault.hashing.config.VaultProperties;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Issues and validates JSON Web Tokens signed with HMAC-SHA256 (use case 1, part 2).
 */
@Service
@Slf4j
public class JwtService {

    private static final int MIN_SECRET_BYTES = 32;

    private final SecretKey key;
    private final String issuer;
    private final Duration ttl;

    public record TokenPrincipal(String username, List<String> roles) {
    }

    public JwtService(VaultProperties properties) {
        VaultProperties.Jwt cfg = properties.getJwt();
        byte[] secret = cfg.getSecret().getBytes(StandardCharsets.UTF_8);
        if (secret.length < MIN_SECRET_BYTES) {
            throw new IllegalStateException("vault.jwt.secret must be at least 32 bytes (256 bits) for HS256");
        }
        if (cfg.getSecret().startsWith("dev-only")) {
            log.warn("Using the built-in development JWT secret. Set VAULT_JWT_SECRET before deploying.");
        }
        this.key = Keys.hmacShaKeyFor(secret);
        this.issuer = cfg.getIssuer();
        this.ttl = cfg.getTtl();
    }

    public Duration getTtl() {
        return ttl;
    }

    /**
     * Creates a compact JWS: {@code base64url(header).base64url(claims).base64url(HMAC-SHA256(secret, header.claims))}.
     *
     * <p><b>Why HMAC-SHA256?</b> The API is a single trust domain: the same service signs and verifies, so a
     * symmetric MAC is enough, is far cheaper than RSA/ECDSA and has no key-distribution problem. A MAC makes the
     * token tamper-evident: changing the subject or roles invalidates the tag, and forging a tag requires the
     * secret. If third parties had to verify tokens without being able to mint them, switch to RS256/ES256.
     */
    public String generateToken(String username, Collection<String> roles) {
        Instant now = Instant.now();
        return Jwts.builder()
                .id(UUID.randomUUID().toString())
                .issuer(issuer)
                .subject(username)
                .claim("roles", List.copyOf(roles))
                .issuedAt(Date.from(now))
                .expiration(Date.from(now.plus(ttl)))
                .signWith(key, Jwts.SIG.HS256)
                .compact();
    }

    /** Verifies signature, issuer and expiry. Returns empty for anything invalid; never throws. */
    public Optional<TokenPrincipal> parse(String token) {
        try {
            Claims claims = Jwts.parser()
                    .verifyWith(key)
                    .requireIssuer(issuer)
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();
            String subject = claims.getSubject();
            if (subject == null || subject.isBlank()) {
                return Optional.empty();
            }
            List<?> raw = claims.get("roles", List.class);
            List<String> roles = raw == null ? List.of() : raw.stream().map(String::valueOf).toList();
            return Optional.of(new TokenPrincipal(subject, roles));
        } catch (JwtException | IllegalArgumentException e) {
            log.debug("Rejected JWT: {}", e.getMessage());
            return Optional.empty();
        }
    }
}
