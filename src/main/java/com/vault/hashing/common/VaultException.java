package com.vault.hashing.common;

import org.springframework.http.HttpStatus;

/** Base type for all domain errors; carries the HTTP status that should be returned to the caller. */
public class VaultException extends RuntimeException {

    private final HttpStatus status;

    public VaultException(HttpStatus status, String message) {
        super(message);
        this.status = status;
    }

    public VaultException(HttpStatus status, String message, Throwable cause) {
        super(message, cause);
        this.status = status;
    }

    public HttpStatus getStatus() {
        return status;
    }
}
