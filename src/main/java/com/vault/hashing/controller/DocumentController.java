package com.vault.hashing.controller;

import com.vault.hashing.integrity.DocumentDtos.DedupStats;
import com.vault.hashing.integrity.DocumentDtos.DocumentResponse;
import com.vault.hashing.integrity.DocumentService;
import com.vault.hashing.integrity.DocumentService.DownloadResult;
import lombok.RequiredArgsConstructor;
import org.springframework.core.io.Resource;
import org.springframework.http.ContentDisposition;
import org.springframework.http.HttpHeaders;
import org.springframework.http.InvalidMediaTypeException;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.UUID;

/** Use cases 2 and 3: checksummed upload/download and content deduplication. */
@RestController
@RequestMapping("/api/documents")
@RequiredArgsConstructor
public class DocumentController {

    private static final String SHA256_HEADER = "X-Content-SHA256";

    private final DocumentService documentService;

    /**
     * Streams the upload through SHA-256, deduplicates it and stores metadata. The optional
     * {@code expectedSha256} lets the client prove the bytes arrived uncorrupted (422 if they did not).
     */
    @PostMapping(consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<DocumentResponse> upload(@RequestParam("file") MultipartFile file,
                                                   @RequestParam(value = "expectedSha256", required = false) String expectedSha256,
                                                   Authentication auth) {
        DocumentResponse created = documentService.upload(file, auth.getName(), expectedSha256);
        return ResponseEntity.created(URI.create("/api/documents/" + created.id())).body(created);
    }

    @GetMapping
    public List<DocumentResponse> list(Authentication auth) {
        return documentService.list(auth.getName());
    }

    @GetMapping("/stats")
    public DedupStats stats() {
        return documentService.stats();
    }

    @GetMapping("/{id}")
    public DocumentResponse metadata(@PathVariable UUID id, Authentication auth) {
        return documentService.getMetadata(id, auth.getName(), isAdmin(auth));
    }

    /** Verifies the stored file against its SHA-256 manifest before streaming it; 422 on mismatch. */
    @GetMapping("/download/{id}")
    public ResponseEntity<Resource> download(@PathVariable UUID id, Authentication auth) {
        DownloadResult result = documentService.prepareDownload(id, auth.getName(), isAdmin(auth));
        return ResponseEntity.ok()
                .contentType(parseMediaType(result.contentType()))
                .contentLength(result.sizeBytes())
                .header(HttpHeaders.CONTENT_DISPOSITION,
                        ContentDisposition.attachment().filename(result.filename(), StandardCharsets.UTF_8).build().toString())
                .header(SHA256_HEADER, result.sha256())
                .body(result.resource());
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> delete(@PathVariable UUID id, Authentication auth) {
        documentService.delete(id, auth.getName(), isAdmin(auth));
        return ResponseEntity.noContent().build();
    }

    private static boolean isAdmin(Authentication auth) {
        return auth.getAuthorities().stream().anyMatch(a -> "ROLE_ADMIN".equals(a.getAuthority()));
    }

    private static MediaType parseMediaType(String value) {
        try {
            return MediaType.parseMediaType(value);
        } catch (InvalidMediaTypeException e) {
            return MediaType.APPLICATION_OCTET_STREAM;
        }
    }
}
