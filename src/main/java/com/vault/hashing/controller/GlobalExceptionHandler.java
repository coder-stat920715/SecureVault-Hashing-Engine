package com.vault.hashing.controller;

import com.vault.hashing.common.VaultException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Maps domain exceptions to RFC 7807 problem responses (e.g. checksum mismatch to 422, bad webhook signature to 401).
 * Standard Spring MVC errors (400, 405, 413, ...) are handled by the {@link ResponseEntityExceptionHandler} base class.
 */
@RestControllerAdvice
@Slf4j
public class GlobalExceptionHandler extends ResponseEntityExceptionHandler {

    @ExceptionHandler(VaultException.class)
    public ProblemDetail handleVaultException(VaultException ex) {
        HttpStatus status = ex.getStatus();
        if (status.is5xxServerError()) {
            log.error("Request failed: {}", ex.getMessage(), ex);
        } else {
            log.warn("Request rejected ({}): {}", status.value(), ex.getMessage());
        }
        // Do not leak internals of unexpected server errors; 503 messages are safe and useful.
        String detail = status.is5xxServerError() && status != HttpStatus.SERVICE_UNAVAILABLE
                ? "The server could not complete the request" : ex.getMessage();
        ProblemDetail problem = ProblemDetail.forStatusAndDetail(status, detail);
        problem.setTitle(status.getReasonPhrase());
        return problem;
    }

    @Override
    protected ResponseEntity<Object> handleMethodArgumentNotValid(MethodArgumentNotValidException ex,
                                                                  HttpHeaders headers, HttpStatusCode status,
                                                                  WebRequest request) {
        Map<String, String> errors = new LinkedHashMap<>();
        ex.getBindingResult().getFieldErrors().forEach(fe -> errors.putIfAbsent(fe.getField(), fe.getDefaultMessage()));
        ProblemDetail problem = ProblemDetail.forStatusAndDetail(HttpStatus.BAD_REQUEST, "Validation failed");
        problem.setTitle("Bad Request");
        problem.setProperty("errors", errors);
        return handleExceptionInternal(ex, problem, headers, HttpStatus.BAD_REQUEST, request);
    }
}
