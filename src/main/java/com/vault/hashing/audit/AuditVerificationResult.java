package com.vault.hashing.audit;

import java.time.Instant;

/**
 * Outcome of walking the whole chain.
 *
 * @param intact              true when every block links to its predecessor and re-hashes to its stored value
 * @param blocksVerified      number of blocks successfully verified before stopping
 * @param firstInvalidBlockId id of the first broken block, or null when intact
 * @param reason              human-readable explanation, or null when intact
 * @param headHash            hash of the newest verified block; anchor it externally to detect tail truncation
 */
public record AuditVerificationResult(boolean intact, long blocksVerified, Long firstInvalidBlockId,
                                      String reason, String headHash, Instant verifiedAt) {
}
