package com.vault.hashing.integrity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.Instant;
import java.util.UUID;

/** Upload record: user-facing metadata plus the SHA-256 manifest used to verify downloads. */
@Entity
@Table(name = "documents", indexes = {
        @Index(name = "idx_doc_owner", columnList = "owner_username"),
        @Index(name = "idx_doc_sha256", columnList = "sha256")
})
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class StoredDocument {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(name = "owner_username", nullable = false, length = 50, updatable = false)
    private String ownerUsername;

    @Column(name = "original_filename", nullable = false, length = 255, updatable = false)
    private String originalFilename;

    @Column(name = "content_type", nullable = false, length = 255, updatable = false)
    private String contentType;

    @Column(name = "size_bytes", nullable = false, updatable = false)
    private long sizeBytes;

    /** The integrity manifest: SHA-256 (hex) computed while the upload was streamed. */
    @Column(name = "sha256", nullable = false, length = 64, updatable = false)
    private String sha256;

    /** True when this upload was linked to an already stored file instead of writing a new one. */
    @Column(name = "deduplicated", nullable = false, updatable = false)
    private boolean deduplicated;

    @ManyToOne(fetch = FetchType.EAGER, optional = false)
    @JoinColumn(name = "blob_id", nullable = false, updatable = false)
    private StoredBlob blob;

    @Column(name = "uploaded_at", nullable = false, updatable = false)
    private Instant uploadedAt;
}
