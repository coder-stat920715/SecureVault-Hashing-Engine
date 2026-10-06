package com.vault.hashing.integrity;

import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Exact-match content deduplication (use case 3).
 *
 * <p>Two layers are used:
 * <ol>
 *   <li>an in-memory {@link Set} of known content hashes: a constant-time membership test that lets the common
 *       "this is a brand new file" case skip the database entirely;</li>
 *   <li>the unique-indexed {@code stored_blobs.content_hash} column, the source of truth and last line of defence
 *       against duplicate physical files, even if the in-memory set is stale.</li>
 * </ol>
 *
 * <p><b>Why a cryptographic hash?</b> Deduplication treats "same hash" as "same bytes". That is only safe when
 * finding two different inputs with the same hash is infeasible, which holds for SHA-256 but not for MD5/SHA-1.
 *
 * <p>Security note: cross-user deduplication reveals that someone already stored a file (the {@code deduplicated}
 * flag in the response). Use per-tenant deduplication if that side channel matters for your threat model.
 */
@Service
@Slf4j
public class DeduplicationService {

    private static final int LOCK_STRIPES = 64;

    private final StoredBlobRepository blobRepository;
    private final Set<String> knownHashes = ConcurrentHashMap.newKeySet();
    private final Object[] locks = new Object[LOCK_STRIPES];

    public DeduplicationService(StoredBlobRepository blobRepository) {
        this.blobRepository = blobRepository;
        for (int i = 0; i < LOCK_STRIPES; i++) {
            locks[i] = new Object();
        }
    }

    @PostConstruct
    void warmUp() {
        knownHashes.addAll(blobRepository.findAllContentHashes());
        log.info("Deduplication index warmed with {} content hashes", knownHashes.size());
    }

    /**
     * Looks up an existing blob for the given content hash.
     *
     * @param authoritative when true the in-memory hint is bypassed and the database is always consulted
     */
    public Optional<StoredBlob> findExisting(String contentHash, boolean authoritative) {
        if (!authoritative && !knownHashes.contains(contentHash)) {
            return Optional.empty();
        }
        Optional<StoredBlob> blob = blobRepository.findByContentHash(contentHash);
        blob.ifPresent(b -> knownHashes.add(contentHash));
        return blob;
    }

    public void markKnown(String contentHash) {
        knownHashes.add(contentHash);
    }

    public void forget(String contentHash) {
        knownHashes.remove(contentHash);
    }

    public long knownHashCount() {
        return knownHashes.size();
    }

    /**
     * Striped lock keyed by content hash: serialises check-then-insert and delete for the same content inside
     * this JVM while letting unrelated uploads proceed in parallel. For multi-instance deployments the unique
     * database index remains the arbiter and the service retries once on a constraint violation.
     */
    public Object lockFor(String contentHash) {
        return locks[(contentHash.hashCode() & 0x7fffffff) % LOCK_STRIPES];
    }
}
