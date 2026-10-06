package com.vault.hashing.audit;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.Immutable;

import java.time.Instant;

/**
 * One block of the audit chain. The entity is {@link Immutable}, has no setters, and every column is
 * non-updatable. The {@code previous_event_hash} unique constraint prevents the chain from forking.
 */
@Entity
@Immutable
@Table(name = "audit_log",
        uniqueConstraints = @UniqueConstraint(name = "uk_audit_previous_hash", columnNames = "previous_event_hash"))
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class AuditLog {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "timestamp", nullable = false, updatable = false)
    private Instant timestamp;

    @Enumerated(EnumType.STRING)
    @Column(name = "action", nullable = false, length = 32, updatable = false)
    private AuditAction action;

    @Column(name = "payload_hash", nullable = false, length = 64, updatable = false)
    private String payloadHash;

    @Column(name = "previous_event_hash", nullable = false, length = 64, updatable = false)
    private String previousEventHash;

    @Column(name = "current_block_hash", nullable = false, length = 64, updatable = false)
    private String currentBlockHash;

    @Builder
    private AuditLog(Instant timestamp, AuditAction action, String payloadHash,
                     String previousEventHash, String currentBlockHash) {
        this.timestamp = timestamp;
        this.action = action;
        this.payloadHash = payloadHash;
        this.previousEventHash = previousEventHash;
        this.currentBlockHash = currentBlockHash;
    }
}
