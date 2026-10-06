package com.vault.hashing.audit;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.repository.Repository;

import java.util.Optional;

/**
 * Deliberately append-only: extends the marker {@link Repository} and exposes no update or delete methods,
 * so application code cannot rewrite history through this API.
 */
public interface AuditLogRepository extends Repository<AuditLog, Long> {

    <S extends AuditLog> S save(S entity);

    Optional<AuditLog> findTopByOrderByIdDesc();

    Page<AuditLog> findAll(Pageable pageable);

    long count();
}
