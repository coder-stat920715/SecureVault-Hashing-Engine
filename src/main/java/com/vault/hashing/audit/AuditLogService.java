package com.vault.hashing.audit;

import com.vault.hashing.common.HashUtils;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionTemplate;

import java.time.Clock;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.locks.ReentrantLock;

/**
 * Tamper-evident, hash-chained audit ledger (use case 5), the same idea as Git commits or blockchain blocks.
 *
 * <pre>
 *   block[n].currentBlockHash = SHA-256(block[n].previousEventHash | timestamp | action | payloadHash)
 *   block[n].previousEventHash = block[n-1].currentBlockHash        (genesis: 64 zeros)
 * </pre>
 *
 * Changing, deleting or reordering any historical block changes its hash, which no longer matches the
 * {@code previousEventHash} stored in its successor, so {@link #verifyChain()} detects it.
 *
 * <p>Limits worth knowing: someone who can rewrite <em>every</em> later block can re-chain the history, and
 * deleting the newest blocks leaves a valid shorter chain. Periodically publish {@code headHash} to a system the
 * database administrator does not control (WORM storage, a second database, a signed timestamp) to close both gaps.
 */
@Service
@Slf4j
public class AuditLogService {

    public static final String GENESIS_HASH = "0".repeat(64);
    private static final int VERIFY_PAGE_SIZE = 500;

    private final AuditLogRepository repository;
    private final Clock clock;
    private final TransactionTemplate appendTx;
    private final ReentrantLock appendLock = new ReentrantLock();

    public AuditLogService(AuditLogRepository repository, Clock clock, PlatformTransactionManager txManager) {
        this.repository = repository;
        this.clock = clock;
        this.appendTx = new TransactionTemplate(txManager);
        // Own transaction: an audit entry is committed (and the chain head advanced) independently of the caller.
        this.appendTx.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
    }

    /**
     * Appends a block. Appends are serialised by a lock because every block depends on the previous head;
     * the unique index on {@code previous_event_hash} additionally rejects forks written by other instances.
     *
     * @param payload canonical description of the event; only its SHA-256 is stored in the ledger
     */
    public AuditLog record(AuditAction action, String payload) {
        Objects.requireNonNull(action, "action");
        Objects.requireNonNull(payload, "payload");
        String payloadHash = HashUtils.sha256Hex(payload);

        appendLock.lock();
        try {
            return appendTx.execute(status -> {
                String previous = repository.findTopByOrderByIdDesc()
                        .map(AuditLog::getCurrentBlockHash)
                        .orElse(GENESIS_HASH);
                // Millisecond precision: survives a database round trip unchanged, so verification is exact.
                Instant timestamp = Instant.now(clock).truncatedTo(ChronoUnit.MILLIS);
                String current = computeBlockHash(previous, timestamp, action, payloadHash);
                return repository.save(AuditLog.builder()
                        .timestamp(timestamp)
                        .action(action)
                        .payloadHash(payloadHash)
                        .previousEventHash(previous)
                        .currentBlockHash(current)
                        .build());
            });
        } finally {
            appendLock.unlock();
        }
    }

    /**
     * {@code SHA-256(previousEventHash | timestampMillis | action | payloadHash)}.
     *
     * <p><b>Why SHA-256?</b> A hash chain is only as strong as the collision/second-preimage resistance of its
     * hash: an attacker who could find another block with the same hash could substitute it without breaking
     * the link. SHA-256 provides that, and its avalanche behaviour means any single-bit change to a block
     * produces an unrelated digest. A {@code |} delimiter is added between fields so that field boundaries are
     * unambiguous (domain separation).
     */
    public static String computeBlockHash(String previousEventHash, Instant timestamp, AuditAction action,
                                          String payloadHash) {
        String material = previousEventHash + '|' + timestamp.toEpochMilli() + '|' + action.name() + '|' + payloadHash;
        return HashUtils.sha256Hex(material);
    }

    /** Walks the entire chain from genesis to head and reports the first inconsistency, if any. */
    @Transactional(readOnly = true)
    public AuditVerificationResult verifyChain() {
        String expectedPrevious = GENESIS_HASH;
        long verified = 0;
        int page = 0;
        Page<AuditLog> current;

        do {
            current = repository.findAll(PageRequest.of(page++, VERIFY_PAGE_SIZE, Sort.by(Sort.Direction.ASC, "id")));
            for (AuditLog block : current.getContent()) {
                if (!expectedPrevious.equals(block.getPreviousEventHash())) {
                    return broken(verified, block.getId(), expectedPrevious,
                            "previousEventHash does not match the preceding block (block removed, inserted or reordered)");
                }
                String recomputed = computeBlockHash(block.getPreviousEventHash(), block.getTimestamp(),
                        block.getAction(), block.getPayloadHash());
                if (!recomputed.equals(block.getCurrentBlockHash())) {
                    return broken(verified, block.getId(), expectedPrevious,
                            "currentBlockHash does not match the block content (block modified)");
                }
                expectedPrevious = block.getCurrentBlockHash();
                verified++;
            }
        } while (current.hasNext());

        return new AuditVerificationResult(true, verified, null, null,
                verified == 0 ? null : expectedPrevious, Instant.now(clock));
    }

    @Transactional(readOnly = true)
    public List<AuditLog> latest(int limit) {
        int size = Math.min(Math.max(limit, 1), 200);
        return repository.findAll(PageRequest.of(0, size, Sort.by(Sort.Direction.DESC, "id"))).getContent();
    }

    private AuditVerificationResult broken(long verified, Long blockId, String lastGoodHash, String reason) {
        log.error("Audit chain broken at block {}: {}", blockId, reason);
        return new AuditVerificationResult(false, verified, blockId, reason,
                verified == 0 ? null : lastGoodHash, Instant.now(clock));
    }
}
