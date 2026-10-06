package com.vault.hashing.audit;

/** Vault events recorded in the hash-chained audit ledger. */
public enum AuditAction {
    UPLOAD,
    DELETE,
    ACCESS,
    WEBHOOK_RECEIVED
}
