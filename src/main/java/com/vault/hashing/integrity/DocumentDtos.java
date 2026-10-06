package com.vault.hashing.integrity;

import java.time.Instant;
import java.util.UUID;

/** Payloads of the document API. */
public final class DocumentDtos {

    private DocumentDtos() {
    }

    public record DocumentResponse(UUID id, String filename, String contentType, long sizeBytes, String sha256,
                                   boolean deduplicated, String storagePath, Instant uploadedAt) {

        public static DocumentResponse from(StoredDocument d) {
            return new DocumentResponse(d.getId(), d.getOriginalFilename(), d.getContentType(), d.getSizeBytes(),
                    d.getSha256(), d.isDeduplicated(), d.getBlob().getStoragePath(), d.getUploadedAt());
        }
    }

    public record DedupStats(long logicalDocuments, long physicalBlobs, long logicalBytes, long physicalBytes,
                             long bytesSaved, long hashesInMemoryIndex) {
    }
}
