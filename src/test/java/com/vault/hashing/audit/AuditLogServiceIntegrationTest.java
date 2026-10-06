package com.vault.hashing.audit;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SpringBootTest(properties = {
        "spring.datasource.url=jdbc:h2:mem:audit-test;DB_CLOSE_DELAY=-1",
        "vault.storage.root-dir=target/test-storage"
})
class AuditLogServiceIntegrationTest {

    @Autowired
    private AuditLogService auditLogService;
    @Autowired
    private JdbcTemplate jdbc;

    @BeforeEach
    void cleanLedger() {
        jdbc.update("delete from audit_log");
    }

    @Test
    void emptyLedgerIsIntact() {
        assertTrue(auditLogService.verifyChain().intact());
    }

    @Test
    void untouchedChainVerifiesAndLinksBlocks() {
        AuditLog first = auditLogService.record(AuditAction.UPLOAD, "a");
        AuditLog second = auditLogService.record(AuditAction.ACCESS, "b");
        auditLogService.record(AuditAction.DELETE, "c");

        assertEquals(AuditLogService.GENESIS_HASH, first.getPreviousEventHash());
        assertEquals(first.getCurrentBlockHash(), second.getPreviousEventHash());

        AuditVerificationResult result = auditLogService.verifyChain();
        assertTrue(result.intact());
        assertEquals(3, result.blocksVerified());
        assertNotNull(result.headHash());
    }

    @Test
    void modifiedBlockIsDetected() {
        AuditLog first = auditLogService.record(AuditAction.UPLOAD, "a");
        auditLogService.record(AuditAction.ACCESS, "b");

        jdbc.update("update audit_log set payload_hash = ? where id = ?", "f".repeat(64), first.getId());

        AuditVerificationResult result = auditLogService.verifyChain();
        assertFalse(result.intact());
        assertEquals(first.getId(), result.firstInvalidBlockId());
    }

    @Test
    void deletedMiddleBlockIsDetected() {
        auditLogService.record(AuditAction.UPLOAD, "a");
        AuditLog middle = auditLogService.record(AuditAction.ACCESS, "b");
        AuditLog last = auditLogService.record(AuditAction.DELETE, "c");

        jdbc.update("delete from audit_log where id = ?", middle.getId());

        AuditVerificationResult result = auditLogService.verifyChain();
        assertFalse(result.intact());
        assertEquals(last.getId(), result.firstInvalidBlockId());
    }
}
