package com.chiffrium.api;

import com.chiffrium.application.security.Actor;
import com.chiffrium.application.security.AuthService.AuthenticatedSession;
import com.chiffrium.application.security.AuthenticationException;
import io.javalin.http.Context;

import java.util.Locale;

/**
 * Accès aux informations d'authentification attachées à une requête par le filtre de l'{@link ApiServer}.
 */
final class RequestContext {

    private static final String SESSION_ATTRIBUTE = "chiffrium.session";
    private static final String BEARER_PREFIX = "bearer ";

    private RequestContext() {
    }

    static void attach(Context ctx, AuthenticatedSession session) {
        ctx.attribute(SESSION_ATTRIBUTE, session);
    }

    static AuthenticatedSession session(Context ctx) {
        AuthenticatedSession session = ctx.attribute(SESSION_ATTRIBUTE);
        if (session == null) {
            throw new AuthenticationException("Authentification requise.");
        }
        return session;
    }

    static Actor actor(Context ctx) {
        return session(ctx).actor();
    }

    /** Jeton porté par l'en-tête {@code Authorization: Bearer ...}, ou null. */
    static String bearerToken(Context ctx) {
        String header = ctx.header("Authorization");
        if (header == null || !header.toLowerCase(Locale.ROOT).startsWith(BEARER_PREFIX)) {
            return null;
        }
        return header.substring(BEARER_PREFIX.length()).trim();
    }

    static String sourceIp(Context ctx) {
        return ctx.ip();
    }
}
