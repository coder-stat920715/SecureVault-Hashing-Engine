package com.vault.hashing.integrity;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.Optional;

public interface StoredBlobRepository extends JpaRepository<StoredBlob, Long> {

    Optional<StoredBlob> findByContentHash(String contentHash);

    @Query("select b.contentHash from StoredBlob b")
    List<String> findAllContentHashes();

    /** Atomic increment in SQL, so concurrent uploads cannot lose updates. */
    @Modifying(flushAutomatically = true, clearAutomatically = true)
    @Query("update StoredBlob b set b.referenceCount = b.referenceCount + 1 where b.id = :id")
    int incrementReferenceCount(@Param("id") Long id);

    @Modifying(flushAutomatically = true, clearAutomatically = true)
    @Query("update StoredBlob b set b.referenceCount = b.referenceCount - 1 where b.id = :id")
    int decrementReferenceCount(@Param("id") Long id);

    @Query("select coalesce(sum(b.sizeBytes), 0) from StoredBlob b")
    long sumSizeBytes();
}
