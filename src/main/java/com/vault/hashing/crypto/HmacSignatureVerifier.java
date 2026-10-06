package com.vault.hashing.crypto;

import com.vault.hashing.common.VaultExceptions.WebhookAuthenticationException;
import com.vault.hashing.config.VaultProperties;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.springframework.stereotype.Component;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;

/**
 * Authenticates webhook callbacks with HMAC-SHA256 (use case 4).
 *
 * <p>The sender computes {@code HMAC-SHA256(sharedSecret, rawBody)} and sends it as
 * {@code X-Vault-Signature: sha256=<hex>}. The receiver recomputes the tag over the <em>exact raw bytes</em>
 * it received and compares.
 */
@Component
@Slf4j
public class HmacSignatureVerifier {

    public static final String HEADER_NAME = "X-Vault-Signature";
    private static final String SCHEME_PREFIX = "sha256=";
    private static final String HMAC_ALGORITHM = "HmacSHA256";

    private final SecretKeySpec keySpec;

    public HmacSignatureVerifier(VaultProperties properties) {
        String secret = properties.getWebhook().getSecret();
        if (secret == null || secret.length() < 16) {
            throw new IllegalStateException("vault.webhook.secret must be at least 16 characters");
        }
        this.keySpec = new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), HMAC_ALGORITHM);
    }

    /** Produces the header value a legitimate sender would attach to this payload. */
    public String sign(byte[] payload) {
        return SCHEME_PREFIX + Hex.encodeHexString(hmac(payload));
    }

    /**
     * Verifies the signature header against the payload.
     *
     * <p><b>Why HMAC and not a plain hash?</b> {@code SHA256(secret + body)} is vulnerable to length-extension
     * attacks, and an unkeyed hash can be recomputed by anyone who alters the body. HMAC is a keyed
     * construction proven secure when the underlying hash is a PRF: only a holder of the shared secret can
     * produce a valid tag, so a valid tag proves both <em>authenticity</em> (sender knows the secret) and
     * <em>integrity</em> (body unchanged).
     *
     * <p>The comparison uses {@link MessageDigest#isEqual(byte[], byte[])}, which is constant-time, so response
     * latency cannot be used to guess the tag byte by byte (timing attack).
     *
     * @throws WebhookAuthenticationException (HTTP 401) when the header is absent, malformed or wrong
     */
    public void verify(byte[] payload, String signatureHeader) {
        if (signatureHeader == null || signatureHeader.isBlank()) {
            throw reject("missing " + HEADER_NAME + " header");
        }
        String header = signatureHeader.trim();
        if (!header.regionMatches(true, 0, SCHEME_PREFIX, 0, SCHEME_PREFIX.length())) {
            throw reject("unsupported signature scheme");
        }
        byte[] provided;
        try {
            provided = Hex.decodeHex(header.substring(SCHEME_PREFIX.length()));
        } catch (DecoderException e) {
            throw reject("signature is not valid hexadecimal");
        }
        byte[] expected = hmac(payload == null ? new byte[0] : payload);
        if (!MessageDigest.isEqual(expected, provided)) {
            throw reject("signature mismatch (tampered payload or wrong secret)");
        }
    }

    private byte[] hmac(byte[] payload) {
        try {
            Mac mac = Mac.getInstance(HMAC_ALGORITHM); // Mac is stateful: one instance per computation
            mac.init(keySpec);
            return mac.doFinal(payload);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("HMAC-SHA256 is unavailable", e);
        }
    }

    private WebhookAuthenticationException reject(String reason) {
        log.warn("Webhook rejected: {}", reason); // the precise reason is logged, never returned to the caller
        return new WebhookAuthenticationException("Invalid or missing webhook signature");
    }
}
