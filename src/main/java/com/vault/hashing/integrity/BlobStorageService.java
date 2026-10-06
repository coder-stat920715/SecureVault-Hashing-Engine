package com.vault.hashing.integrity;

import com.vault.hashing.common.VaultExceptions.StorageException;
import com.vault.hashing.config.VaultProperties;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * Content-addressable file store. A blob's location is a pure function of its SHA-256
 * ({@code root/ab/cd/abcdef...}), so user-supplied file names never touch the file system
 * (no path traversal) and identical content always maps to the same path.
 */
@Service
@Slf4j
public class BlobStorageService {

    private final Path root;
    private final Path tempDir;

    public BlobStorageService(VaultProperties properties) {
        this.root = Paths.get(properties.getStorage().getRootDir()).toAbsolutePath().normalize();
        this.tempDir = root.resolve(".tmp");
        try {
            Files.createDirectories(tempDir);
        } catch (IOException e) {
            throw new IllegalStateException("Cannot create storage directory " + tempDir, e);
        }
    }

    /** Staging area on the same file system as the store, so the final move is a cheap rename. */
    public Path tempDirectory() {
        return tempDir;
    }

    public String relativePathFor(String sha256Hex) {
        return sha256Hex.substring(0, 2) + "/" + sha256Hex.substring(2, 4) + "/" + sha256Hex;
    }

    public Path resolve(String relativePath) {
        Path resolved = root.resolve(relativePath).normalize();
        if (!resolved.startsWith(root)) {
            throw new StorageException("Resolved path escapes the storage root");
        }
        return resolved;
    }

    /**
     * Moves a staged file into its content-addressed location.
     *
     * @return {@code true} if this call created the file, {@code false} if a file already existed there
     * (identical by construction, since the path is derived from the content hash)
     */
    public boolean moveIntoStore(Path staged, String relativePath) {
        Path target = resolve(relativePath);
        try {
            Files.createDirectories(target.getParent());
            if (Files.exists(target)) {
                return false;
            }
            Files.move(staged, target); // no REPLACE_EXISTING: fails instead of overwriting
            return true;
        } catch (FileAlreadyExistsException e) {
            return false;
        } catch (NoSuchFileException e) {
            throw new StorageException("Staged upload disappeared before it could be stored", e);
        } catch (IOException e) {
            throw new StorageException("Unable to store content at " + relativePath, e);
        }
    }

    public void deleteQuietly(String relativePath) {
        deleteQuietly(resolve(relativePath));
    }

    public void deleteQuietly(Path path) {
        if (path == null) {
            return;
        }
        try {
            Files.deleteIfExists(path);
        } catch (IOException e) {
            log.warn("Could not delete {}: {}", path, e.getMessage());
        }
    }
}
