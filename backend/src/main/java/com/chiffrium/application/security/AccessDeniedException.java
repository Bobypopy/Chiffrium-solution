package com.chiffrium.application.security;

/**
 * Action refusée faute de permission (HTTP 403).
 */
public class AccessDeniedException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    public AccessDeniedException(String message) {
        super(message);
    }
}
