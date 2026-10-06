package com.vault.hashing.integrity;

import com.vault.hashing.common.HashUtils;
import com.vault.hashing.common.VaultExceptions.StorageException;
import org.apache.commons.codec.binary.Hex;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.security.DigestInputStream;
import java.security.MessageDigest;

/** Streaming SHA-256 checksums (use case 2). Files are never loaded fully into memory. */
@Service
public class ChecksumService {

    private static final int BUFFER_SIZE = 64 * 1024;

    /** Result of staging an upload: where it was written, its SHA-256 and its size. */
    public record StreamedContent(Path path, String sha256, long size) {
    }

    /**
     * Copies the stream to a temporary file while feeding every byte through a SHA-256 digest, in one pass.
     *
     * <p><b>Why SHA-256?</b> It is collision resistant (MD5 and SHA-1 are practically broken: attackers can craft
     * two different files with the same digest, which would defeat both integrity checks and deduplication),
     * fast enough for multi-GB streams, available in every JVM, and produces a 256-bit value that is easy to
     * publish as a manifest. A {@link DigestInputStream} lets the digest be computed without a second read.
     */
    public StreamedContent streamToTempFile(InputStream source, Path tempDir) {
        Path temp = null;
        try {
            temp = Files.createTempFile(tempDir, "upload-", ".part");
            MessageDigest digest = HashUtils.newSha256();
            long size;
            try (InputStream in = new DigestInputStream(source, digest);
                 OutputStream out = Files.newOutputStream(temp)) {
                size = in.transferTo(out);
            }
            return new StreamedContent(temp, Hex.encodeHexString(digest.digest()), size);
        } catch (IOException e) {
            if (temp != null) {
                try {
                    Files.deleteIfExists(temp);
                } catch (IOException ignored) {
                    // best effort cleanup
                }
            }
            throw new StorageException("Failed to stage the uploaded content", e);
        }
    }

    /** Re-computes the SHA-256 of a stored file by streaming it in fixed-size chunks. */
    public String sha256OfFile(Path file) {
        MessageDigest digest = HashUtils.newSha256();
        byte[] buffer = new byte[BUFFER_SIZE];
        try (InputStream in = Files.newInputStream(file)) {
            int read;
            while ((read = in.read(buffer)) != -1) {
                digest.update(buffer, 0, read);
            }
            return Hex.encodeHexString(digest.digest());
        } catch (NoSuchFileException e) {
            throw new StorageException("Stored content is missing from the file store", e);
        } catch (IOException e) {
            throw new StorageException("Unable to read stored content", e);
        }
    }
}
