package com.vault.hashing.common;

import org.springframework.http.HttpStatus;

/** Concrete domain exceptions, grouped in one holder to keep the package small. */
public final class VaultExceptions {

    private VaultExceptions() {
    }

    public static class BadRequestException extends VaultException {
        public BadRequestException(String message) {
            super(HttpStatus.BAD_REQUEST, message);
        }
    }

    public static class InvalidCredentialsException extends VaultException {
        public InvalidCredentialsException() {
            super(HttpStatus.UNAUTHORIZED, "Invalid username or password");
        }
    }

    /** Raised when a webhook signature is missing, malformed or does not match (HTTP 401). */
    public static class WebhookAuthenticationException extends VaultException {
        public WebhookAuthenticationException(String message) {
            super(HttpStatus.UNAUTHORIZED, message);
        }
    }

    public static class ResourceNotFoundException extends VaultException {
        public ResourceNotFoundException(String message) {
            super(HttpStatus.NOT_FOUND, message);
        }
    }

    public static class ConflictException extends VaultException {
        public ConflictException(String message) {
            super(HttpStatus.CONFLICT, message);
        }
    }

    /** Raised when a checksum does not match its manifest (HTTP 422). */
    public static class IntegrityViolationException extends VaultException {
        public IntegrityViolationException(String message) {
            super(HttpStatus.UNPROCESSABLE_ENTITY, message);
        }
    }

    public static class StorageException extends VaultException {
        public StorageException(String message) {
            super(HttpStatus.INTERNAL_SERVER_ERROR, message);
        }

        public StorageException(String message, Throwable cause) {
            super(HttpStatus.INTERNAL_SERVER_ERROR, message, cause);
        }
    }

    public static class NoWorkerAvailableException extends VaultException {
        public NoWorkerAvailableException(String message) {
            super(HttpStatus.SERVICE_UNAVAILABLE, message);
        }
    }
}
