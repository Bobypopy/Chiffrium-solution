package com.chiffrium.application.security;

/**
 * Authentification absente, invalide ou expirée (HTTP 401). Le message reste volontairement générique
 * pour ne pas révéler si un identifiant existe.
 */
public class AuthenticationException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    public AuthenticationException(String message) {
        super(message);
    }
}
