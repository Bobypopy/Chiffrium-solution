package com.chiffrium.api;

import com.chiffrium.application.security.AccessDeniedException;
import com.chiffrium.application.security.AuthService;
import com.chiffrium.application.security.AuthService.LoginResult;
import com.chiffrium.application.security.AuthenticationException;
import com.chiffrium.application.security.SsoService;
import com.chiffrium.domain.security.User;
import io.javalin.Javalin;
import io.javalin.http.Context;
import io.javalin.http.HttpStatus;

import java.time.Instant;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Authentification : état d'installation, création du premier administrateur, connexion, session courante,
 * changement de mot de passe, déconnexion, authentification unique OIDC.
 */
final class AuthRoutes {

    /** Pages de l'interface vers lesquelles le retour SSO redirige (chemins fixes : pas de redirection ouverte). */
    static final String SSO_SUCCESS_PAGE = "/#/sso/";
    static final String SSO_FAILURE_PAGE = "/#/login?sso=echec";

    private final AuthService auth;
    private final SsoService sso;
    private final LoginThrottle throttle;

    AuthRoutes(AuthService auth, SsoService sso, LoginThrottle throttle) {
        this.auth = auth;
        this.sso = sso;
        this.throttle = throttle;
    }

    record LoginRequest(String username, char[] password) {
    }

    record SetupRequest(String setupToken, String username, char[] password, String displayName) {
    }

    record ChangePasswordRequest(char[] currentPassword, char[] newPassword) {
    }

    record TicketRequest(String ticket) {
    }

    /** Réponse de connexion : le jeton n'est transmis qu'ici. */
    record SessionResponse(String token, Instant expiresAt, User user) {
        static SessionResponse of(LoginResult result) {
            return new SessionResponse(result.token(), result.expiresAt(), result.user());
        }
    }

    void register(Javalin server) {
        server.get(ApiServer.AUTH_STATUS_PATH, this::status);
        server.post(ApiServer.AUTH_SETUP_PATH, this::setup);
        server.post(ApiServer.AUTH_LOGIN_PATH, this::login);
        server.get(ApiServer.AUTH_ME_PATH, this::me);
        server.post(ApiServer.AUTH_PASSWORD_PATH, this::changePassword);
        server.post(ApiServer.AUTH_LOGOUT_PATH, this::logout);
        server.get(ApiServer.OIDC_START_PATH, ctx -> ctx.json(Map.of("authorizationUrl", sso.start())));
        server.get(ApiServer.OIDC_CALLBACK_PATH, this::oidcCallback);
        server.post(ApiServer.OIDC_EXCHANGE_PATH, ctx ->
                ctx.json(SessionResponse.of(sso.redeem(ctx.bodyAsClass(TicketRequest.class).ticket()))));
    }

    private void status(Context ctx) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("setupRequired", auth.setupRequired());
        body.put("oidcEnabled", sso.enabled());
        ctx.json(body);
    }

    private void setup(Context ctx) {
        SetupRequest request = ctx.bodyAsClass(SetupRequest.class);
        String ip = RequestContext.sourceIp(ctx);
        guardThrottle(ip);
        try {
            LoginResult result = auth.setup(request.setupToken(), request.username(), request.password(),
                    request.displayName(), ip);
            ctx.status(HttpStatus.CREATED).json(SessionResponse.of(result));
        } catch (AuthenticationException e) {
            throttle.recordFailure(ip);
            throw e;
        } finally {
            wipe(request.password());
        }
    }

    private void login(Context ctx) {
        LoginRequest request = ctx.bodyAsClass(LoginRequest.class);
        String ip = RequestContext.sourceIp(ctx);
        guardThrottle(ip);
        try {
            LoginResult result = auth.login(request.username(), request.password(), ip);
            throttle.reset(ip);
            ctx.json(SessionResponse.of(result));
        } catch (AuthenticationException e) {
            throttle.recordFailure(ip);
            throw e;
        } finally {
            wipe(request.password());
        }
    }

    private void me(Context ctx) {
        User user = RequestContext.session(ctx).user();
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("user", user);
        body.put("permissions", user.role().permissions());
        ctx.json(body);
    }

    private void changePassword(Context ctx) {
        ChangePasswordRequest request = ctx.bodyAsClass(ChangePasswordRequest.class);
        try {
            LoginResult result = auth.changePassword(RequestContext.actor(ctx), request.currentPassword(),
                    request.newPassword());
            ctx.json(SessionResponse.of(result));
        } finally {
            wipe(request.currentPassword());
            wipe(request.newPassword());
        }
    }

    private void logout(Context ctx) {
        auth.logout(RequestContext.bearerToken(ctx), RequestContext.actor(ctx));
        ctx.status(HttpStatus.NO_CONTENT);
    }

    /** Retour du fournisseur d'identité : le navigateur est renvoyé vers l'interface avec un ticket éphémère. */
    private void oidcCallback(Context ctx) {
        String ip = RequestContext.sourceIp(ctx);
        guardThrottle(ip);
        if (ctx.queryParam("error") != null) {
            throttle.recordFailure(ip);
            ctx.redirect(SSO_FAILURE_PAGE);
            return;
        }
        try {
            ctx.redirect(SSO_SUCCESS_PAGE + sso.complete(ctx.queryParam("state"), ctx.queryParam("code"), ip));
        } catch (AuthenticationException | AccessDeniedException e) {
            throttle.recordFailure(ip);
            ctx.redirect(SSO_FAILURE_PAGE);
        }
    }

    private void guardThrottle(String ip) {
        if (throttle.isBlocked(ip)) {
            throw new ApiServer.TooManyAttempts("Trop de tentatives depuis cette adresse. Réessayer dans quelques minutes.");
        }
    }

    private static void wipe(char[] secret) {
        if (secret != null) {
            Arrays.fill(secret, '\0');
        }
    }
}
