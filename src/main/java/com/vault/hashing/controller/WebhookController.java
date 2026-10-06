package com.vault.hashing.controller;

import com.vault.hashing.audit.AuditAction;
import com.vault.hashing.audit.AuditLogService;
import com.vault.hashing.common.HashUtils;
import com.vault.hashing.crypto.HmacSignatureVerifier;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/** Use case 4: HMAC-SHA256 authenticated webhook receiver. */
@RestController
@RequestMapping("/api/webhooks")
@RequiredArgsConstructor
public class WebhookController {

    public record WebhookReceipt(String status, String payloadSha256, int bytes) {
    }

    private final HmacSignatureVerifier verifier;
    private final AuditLogService auditLogService;

    /**
     * The body is received as raw bytes on purpose: the signature covers the exact bytes the partner sent, and
     * re-serialising parsed JSON would change whitespace/ordering and break verification.
     * Unsigned or tampered requests are answered with 401 before any processing happens.
     */
    @PostMapping("/partner-event")
    public ResponseEntity<WebhookReceipt> partnerEvent(
            @RequestBody(required = false) byte[] rawBody,
            @RequestHeader(value = HmacSignatureVerifier.HEADER_NAME, required = false) String signature) {

        byte[] body = rawBody == null ? new byte[0] : rawBody;
        verifier.verify(body, signature);

        String bodyHash = HashUtils.sha256Hex(body);
        auditLogService.record(AuditAction.WEBHOOK_RECEIVED,
                "partner-event|bytes=" + body.length + "|sha256=" + bodyHash);
        return ResponseEntity.accepted().body(new WebhookReceipt("accepted", bodyHash, body.length));
    }
}
