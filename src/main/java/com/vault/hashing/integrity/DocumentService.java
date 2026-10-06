package com.vault.hashing.integrity;

import com.vault.hashing.audit.AuditAction;
import com.vault.hashing.audit.AuditLogService;
import com.vault.hashing.common.HashUtils;
import com.vault.hashing.common.VaultExceptions.BadRequestException;
import com.vault.hashing.common.VaultExceptions.ConflictException;
import com.vault.hashing.common.VaultExceptions.IntegrityViolationException;
import com.vault.hashing.common.VaultExceptions.ResourceNotFoundException;
import com.vault.hashing.common.VaultExceptions.StorageException;
import com.vault.hashing.integrity.DocumentDtos.DedupStats;
import com.vault.hashing.integrity.DocumentDtos.DocumentResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.io.PathResource;
import org.springframework.core.io.Resource;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.UUID;

/**
 * Orchestrates upload (streamed SHA-256 + deduplication), verified download and reference-counted deletion.
 * Database work happens inside short {@link TransactionTemplate} blocks so file-system effects and locks are
 * handled outside of, or explicitly synchronised with, the transaction.
 */
@Service
@Slf4j
@RequiredArgsConstructor
public class DocumentService {

    private final StoredDocumentRepository documentRepository;
    private final StoredBlobRepository blobRepository;
    private final ChecksumService checksumService;
    private final DeduplicationService deduplicationService;
    private final BlobStorageService blobStorage;
    private final AuditLogService auditLogService;
    private final TransactionTemplate transactionTemplate;

    public record DownloadResult(Resource resource, String filename, String contentType, long sizeBytes,
                                 String sha256) {
    }

    // ------------------------------------------------------------------ upload

    public DocumentResponse upload(MultipartFile file, String owner, String expectedSha256) {
        if (file == null || file.isEmpty()) {
            throw new BadRequestException("A non-empty multipart part named 'file' is required");
        }
        String expected = null;
        if (expectedSha256 != null && !expectedSha256.isBlank()) {
            expected = expectedSha256.trim().toLowerCase(Locale.ROOT);
            if (!HashUtils.isSha256Hex(expected)) {
                throw new BadRequestException("expectedSha256 must be 64 hexadecimal characters");
            }
        }
        String filename = sanitizeFilename(file.getOriginalFilename());
        String contentType = file.getContentType() != null ? file.getContentType() : MediaType.APPLICATION_OCTET_STREAM_VALUE;

        ChecksumService.StreamedContent staged;
        try (InputStream in = file.getInputStream()) {
            staged = checksumService.streamToTempFile(in, blobStorage.tempDirectory());
        } catch (IOException e) {
            throw new StorageException("Unable to read the uploaded file", e);
        }

        try {
            if (expected != null && !expected.equals(staged.sha256())) {
                throw new IntegrityViolationException("Upload corrupted in transit: client expected SHA-256 "
                        + expected + " but the server received " + staged.sha256());
            }
            StoredDocument saved = persistWithDeduplication(staged, filename, contentType, owner);
            auditLogService.record(AuditAction.UPLOAD, "upload|doc=" + saved.getId() + "|owner=" + owner
                    + "|sha256=" + saved.getSha256() + "|deduplicated=" + saved.isDeduplicated());
            return DocumentResponse.from(saved);
        } finally {
            blobStorage.deleteQuietly(staged.path()); // no-op when the file was moved into the store
        }
    }

    private StoredDocument persistWithDeduplication(ChecksumService.StreamedContent staged, String filename,
                                                    String contentType, String owner) {
        String hash = staged.sha256();
        boolean authoritative = false;
        for (int attempt = 1; ; attempt++) {
            final boolean bypassHint = authoritative;
            try {
                synchronized (deduplicationService.lockFor(hash)) {
                    return transactionTemplate.execute(
                            status -> insertDocument(staged, filename, contentType, owner, bypassHint));
                }
            } catch (DataIntegrityViolationException e) {
                // Another writer (e.g. a second application instance) stored the same content first.
                if (attempt >= 2) {
                    throw new ConflictException("Concurrent upload of identical content; please retry");
                }
                log.info("Duplicate content hash {} raced with another writer; retrying with a DB lookup", hash);
                authoritative = true;
            }
        }
    }

    private StoredDocument insertDocument(ChecksumService.StreamedContent staged, String filename,
                                          String contentType, String owner, boolean authoritative) {
        String hash = staged.sha256();
        Optional<StoredBlob> existing = deduplicationService.findExisting(hash, authoritative);
        StoredBlob blob;
        boolean deduplicated;

        if (existing.isPresent()) {
            // Duplicate: link to the existing physical file and discard the new bytes.
            blob = existing.get();
            deduplicated = true;
            if (blobStorage.moveIntoStore(staged.path(), blob.getStoragePath())) {
                log.warn("Blob {} was missing on disk; restored it from the freshly verified upload", hash);
            }
            blobRepository.incrementReferenceCount(blob.getId());
        } else {
            String relative = blobStorage.relativePathFor(hash);
            boolean createdFile = blobStorage.moveIntoStore(staged.path(), relative);
            registerBlobSynchronization(hash, relative, createdFile);
            blob = blobRepository.save(StoredBlob.builder()
                    .contentHash(hash)
                    .storagePath(relative)
                    .sizeBytes(staged.size())
                    .referenceCount(1)
                    .createdAt(Instant.now())
                    .build());
            deduplicated = false;
        }

        return documentRepository.save(StoredDocument.builder()
                .ownerUsername(owner)
                .originalFilename(filename)
                .contentType(contentType)
                .sizeBytes(staged.size())
                .sha256(hash)
                .deduplicated(deduplicated)
                .blob(blob)
                .uploadedAt(Instant.now())
                .build());
    }

    /** After the DB outcome is known: publish the hash on commit, or remove the orphan file on rollback. */
    private void registerBlobSynchronization(String hash, String relativePath, boolean createdFile) {
        TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization() {
            @Override
            public void afterCompletion(int status) {
                if (status == STATUS_COMMITTED) {
                    deduplicationService.markKnown(hash);
                } else if (createdFile) {
                    blobStorage.deleteQuietly(relativePath);
                }
            }
        });
    }

    // ---------------------------------------------------------------- download

    /**
     * Verifies the stored bytes against the SHA-256 manifest recorded at upload time and only then exposes them.
     * A mismatch (bit rot, truncated or tampered file) raises HTTP 422 before a single byte is returned.
     *
     * <p>Note: the file is verified and then streamed, so a writer with file-system access could swap it in
     * between. Storage directories must therefore not be writable by anything except this service.
     */
    public DownloadResult prepareDownload(UUID id, String username, boolean admin) {
        StoredDocument doc = findAccessible(id, username, admin);
        Path path = blobStorage.resolve(doc.getBlob().getStoragePath());
        String actual = checksumService.sha256OfFile(path);

        if (!actual.equals(doc.getSha256())) {
            log.error("Integrity violation for document {}: manifest={} actual={}", id, doc.getSha256(), actual);
            auditLogService.record(AuditAction.ACCESS, "download-rejected|doc=" + id + "|user=" + username
                    + "|reason=checksum-mismatch|expected=" + doc.getSha256() + "|actual=" + actual);
            throw new IntegrityViolationException("Stored content failed SHA-256 verification; download refused");
        }

        auditLogService.record(AuditAction.ACCESS, "download|doc=" + id + "|user=" + username
                + "|sha256=" + doc.getSha256());
        return new DownloadResult(new PathResource(path), doc.getOriginalFilename(), doc.getContentType(),
                doc.getSizeBytes(), doc.getSha256());
    }

    // ------------------------------------------------------------ read / delete

    public DocumentResponse getMetadata(UUID id, String username, boolean admin) {
        return DocumentResponse.from(findAccessible(id, username, admin));
    }

    public List<DocumentResponse> list(String username) {
        return documentRepository.findByOwnerUsernameOrderByUploadedAtDesc(username).stream()
                .map(DocumentResponse::from).toList();
    }

    public void delete(UUID id, String username, boolean admin) {
        StoredDocument preview = findAccessible(id, username, admin);
        String hash = preview.getSha256();

        synchronized (deduplicationService.lockFor(hash)) {
            String orphanedPath = transactionTemplate.execute(status -> {
                StoredDocument doc = documentRepository.findById(id)
                        .orElseThrow(() -> new ResourceNotFoundException("Document not found: " + id));
                Long blobId = doc.getBlob().getId();
                documentRepository.delete(doc);
                documentRepository.flush();
                blobRepository.decrementReferenceCount(blobId);
                StoredBlob blob = blobRepository.findById(blobId)
                        .orElseThrow(() -> new StorageException("Blob row vanished for document " + id));
                if (blob.getReferenceCount() <= 0) {
                    blobRepository.delete(blob);
                    return blob.getStoragePath();
                }
                return null;
            });
            if (orphanedPath != null) {
                blobStorage.deleteQuietly(orphanedPath);
                deduplicationService.forget(hash);
            }
        }
        auditLogService.record(AuditAction.DELETE, "delete|doc=" + id + "|user=" + username + "|sha256=" + hash);
    }

    public DedupStats stats() {
        long logical = documentRepository.sumSizeBytes();
        long physical = blobRepository.sumSizeBytes();
        return new DedupStats(documentRepository.count(), blobRepository.count(), logical, physical,
                logical - physical, deduplicationService.knownHashCount());
    }

    // ----------------------------------------------------------------- helpers

    /** Non-owners get 404 (not 403) so document ids cannot be probed for existence. */
    private StoredDocument findAccessible(UUID id, String username, boolean admin) {
        StoredDocument doc = documentRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Document not found: " + id));
        if (!admin && !doc.getOwnerUsername().equals(username)) {
            throw new ResourceNotFoundException("Document not found: " + id);
        }
        return doc;
    }

    private static String sanitizeFilename(String original) {
        String name = original == null ? "" : original.replace('\\', '/');
        name = name.substring(name.lastIndexOf('/') + 1).replaceAll("\\p{Cntrl}", "").trim();
        if (name.isEmpty()) {
            name = "unnamed";
        }
        return name.length() > 255 ? name.substring(0, 255) : name;
    }
}
