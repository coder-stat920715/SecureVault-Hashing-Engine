package com.vault.hashing.crypto;

import com.vault.hashing.common.VaultExceptions.WebhookAuthenticationException;
import com.vault.hashing.config.VaultProperties;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class HmacSignatureVerifierTest {

    private static final String SECRET = "unit-test-shared-secret-123456";
    private HmacSignatureVerifier verifier;

    private static HmacSignatureVerifier verifierWith(String secret) {
        VaultProperties props = new VaultProperties();
        props.getWebhook().setSecret(secret);
        return new HmacSignatureVerifier(props);
    }

    @BeforeEach
    void setUp() {
        verifier = verifierWith(SECRET);
    }

    @Test
    void matchesIndependentlyComputedHmac() {
        // Reference value produced with: printf '%s' '{"event":"ping"}' | openssl dgst -sha256 -hmac "<secret>"
        byte[] body = "{\"event\":\"ping\"}".getBytes(StandardCharsets.UTF_8);
        assertEquals("sha256=b24947ae2f05afca9177274d40bac2f9747dbc45327a09f76f7763e1cffc59ae", verifier.sign(body));
    }

    @Test
    void acceptsValidSignature() {
        byte[] body = "{\"a\":1}".getBytes(StandardCharsets.UTF_8);
        assertDoesNotThrow(() -> verifier.verify(body, verifier.sign(body)));
    }

    @Test
    void rejectsTamperedBody() {
        byte[] original = "{\"amount\":10}".getBytes(StandardCharsets.UTF_8);
        byte[] tampered = "{\"amount\":99}".getBytes(StandardCharsets.UTF_8);
        String signature = verifier.sign(original);
        assertThrows(WebhookAuthenticationException.class, () -> verifier.verify(tampered, signature));
    }

    @Test
    void rejectsSignatureFromDifferentSecret() {
        byte[] body = "{}".getBytes(StandardCharsets.UTF_8);
        String forged = verifierWith("another-secret-of-sufficient-length").sign(body);
        assertThrows(WebhookAuthenticationException.class, () -> verifier.verify(body, forged));
    }

    @Test
    void rejectsMissingOrMalformedHeaders() {
        byte[] body = "{}".getBytes(StandardCharsets.UTF_8);
        assertThrows(WebhookAuthenticationException.class, () -> verifier.verify(body, null));
        assertThrows(WebhookAuthenticationException.class, () -> verifier.verify(body, ""));
        assertThrows(WebhookAuthenticationException.class, () -> verifier.verify(body, "md5=abcd"));
        assertThrows(WebhookAuthenticationException.class, () -> verifier.verify(body, "sha256=not-hex"));
    }
}
