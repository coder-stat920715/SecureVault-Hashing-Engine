package com.vault.hashing.integrity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.Instant;

/**
 * One physical file on disk, addressed by the SHA-256 of its content (content-addressable storage).
 * Many {@link StoredDocument}s may point at the same blob; {@code referenceCount} tracks how many.
 *
 * <p>The unique constraint on {@code content_hash} is the "indexed hash lookup table": it gives O(1)-style
 * exact-match lookups and acts as the final guard against duplicate physical files.
 * On PostgreSQL an additional {@code USING HASH} index can be added (see README).
 */
@Entity
@Table(name = "stored_blobs",
        uniqueConstraints = @UniqueConstraint(name = "uk_blob_content_hash", columnNames = "content_hash"))
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class StoredBlob {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "content_hash", nullable = false, length = 64, updatable = false)
    private String contentHash;

    /** Path relative to the storage root, derived from the hash, e.g. {@code ab/cd/abcd...}. */
    @Column(name = "storage_path", nullable = false, length = 512, updatable = false)
    private String storagePath;

    @Column(name = "size_bytes", nullable = false, updatable = false)
    private long sizeBytes;

    @Column(name = "reference_count", nullable = false)
    private int referenceCount;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;
}
