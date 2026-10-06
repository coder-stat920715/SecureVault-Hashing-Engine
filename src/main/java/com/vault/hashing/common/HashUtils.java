package com.vault.hashing.common;

import org.apache.commons.codec.binary.Hex;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.regex.Pattern;

/** Small, dependency-light helpers shared by the hashing modules. */
public final class HashUtils {

    private static final Pattern SHA256_HEX = Pattern.compile("^[0-9a-f]{64}$");

    private HashUtils() {
    }

    /** {@link MessageDigest} instances are stateful and not thread-safe, so always create a fresh one. */
    public static MessageDigest newDigest(String algorithm) {
        try {
            return MessageDigest.getInstance(algorithm);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(algorithm + " is not available in this JVM", e);
        }
    }

    public static MessageDigest newSha256() {
        return newDigest("SHA-256");
    }

    public static String sha256Hex(String text) {
        return sha256Hex(text.getBytes(StandardCharsets.UTF_8));
    }

    public static String sha256Hex(byte[] data) {
        return Hex.encodeHexString(newSha256().digest(data));
    }

    /** True when the value is exactly 64 lowercase hexadecimal characters. */
    public static boolean isSha256Hex(String value) {
        return value != null && SHA256_HEX.matcher(value).matches();
    }
}
