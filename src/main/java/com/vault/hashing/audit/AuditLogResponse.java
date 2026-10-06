package com.vault.hashing.audit;

import java.time.Instant;

public record AuditLogResponse(Long id, Instant timestamp, AuditAction action, String payloadHash,
                               String previousEventHash, String currentBlockHash) {

    public static AuditLogResponse from(AuditLog log) {
        return new AuditLogResponse(log.getId(), log.getTimestamp(), log.getAction(), log.getPayloadHash(),
                log.getPreviousEventHash(), log.getCurrentBlockHash());
    }
}
