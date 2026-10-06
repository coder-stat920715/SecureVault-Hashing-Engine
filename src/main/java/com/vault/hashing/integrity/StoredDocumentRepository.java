package com.vault.hashing.integrity;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.List;
import java.util.UUID;

public interface StoredDocumentRepository extends JpaRepository<StoredDocument, UUID> {

    List<StoredDocument> findByOwnerUsernameOrderByUploadedAtDesc(String ownerUsername);

    @Query("select coalesce(sum(d.sizeBytes), 0) from StoredDocument d")
    long sumSizeBytes();
}
