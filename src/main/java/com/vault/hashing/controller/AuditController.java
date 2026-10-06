package com.vault.hashing.controller;

import com.vault.hashing.audit.AuditLogResponse;
import com.vault.hashing.audit.AuditLogService;
import com.vault.hashing.audit.AuditVerificationResult;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/** Use case 5: inspect and verify the hash-chained audit ledger. */
@RestController
@RequestMapping("/api/audit")
@RequiredArgsConstructor
public class AuditController {

    private final AuditLogService auditLogService;

    /** Re-hashes the entire chain and reports whether the history is intact or where it was tampered with. */
    @GetMapping("/verify")
    public AuditVerificationResult verify() {
        return auditLogService.verifyChain();
    }

    /** Most recent blocks first (limit is clamped to 1..200). */
    @GetMapping("/logs")
    public List<AuditLogResponse> latest(@RequestParam(defaultValue = "50") int limit) {
        return auditLogService.latest(limit).stream().map(AuditLogResponse::from).toList();
    }
}
