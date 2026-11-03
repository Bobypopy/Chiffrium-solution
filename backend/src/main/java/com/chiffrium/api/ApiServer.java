package com.chiffrium.api;

import com.chiffrium.application.AnalysisService;
import com.chiffrium.application.CatalogRequestService;
import com.chiffrium.application.CatalogService;
import com.chiffrium.application.RetentionService;
import com.chiffrium.application.port.AnalysisException;
import com.chiffrium.application.port.AnalysisRepository;
import com.chiffrium.application.security.AccessDeniedException;
import com.chiffrium.application.security.AccountService;
import com.chiffrium.application.security.AuditArchiveService;
import com.chiffrium.application.security.AuditService;
import com.chiffrium.application.security.AuthService;
import com.chiffrium.application.security.AuthService.AuthenticatedSession;
import com.chiffrium.application.security.AuthenticationException;
import com.chiffrium.application.security.GroupService;
import com.chiffrium.application.security.NotificationService;
import com.chiffrium.application.security.SsoService;
import com.chiffrium.application.security.UserService;
import com.chiffrium.application.settings.SettingsService;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.javalin.Javalin;
import io.javalin.http.Context;
import io.javalin.http.HandlerType;
import io.javalin.http.HttpStatus;
import io.javalin.http.staticfiles.Location;
import io.javalin.json.JavalinJackson;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.time.Clock;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.function.Supplier;

/**
 * Adaptateur HTTP (Javalin). Ne contient aucune logique métier : authentification des requêtes,
 * validation des entrées, appel des services, traduction des erreurs en codes HTTP. Les contrôles
 * d'autorisation fins sont faits par les services (défense en profondeur).
 */
public final class ApiServer {

    private static final Logger LOG = LoggerFactory.getLogger(ApiServer.class);
    private static final long MAX_REQUEST_BYTES = 8L * 1_048_576L;
    private static final String FORWARDED_FOR = "X-Forwarded-For";

    static final String AUTH_STATUS_PATH = "/api/auth/status";
    static final String AUTH_SETUP_PATH = "/api/auth/setup";
    static final String AUTH_LOGIN_PATH = "/api/auth/login";
    static final String AUTH_ME_PATH = "/api/auth/me";
    static final String AUTH_PASSWORD_PATH = "/api/auth/change-password";
    static final String AUTH_LOGOUT_PATH = "/api/auth/logout";
    static final String HEALTH_PATH = "/api/health";
    static final String OIDC_START_PATH = "/api/auth/oidc/start";
    static final String OIDC_CALLBACK_PATH = "/api/auth/oidc/callback";
    static final String OIDC_EXCHANGE_PATH = "/api/auth/oidc/exchange";

    /** Routes accessibles sans session. */
    static final String DESKTOP_ACTIVITY_PATH = "/api/desktop/activity";
    static final String DESKTOP_TOKEN_HEADER = "X-Desktop-Token";
    private static final Set<String> PUBLIC_PATHS = Set.of(HEALTH_PATH, DESKTOP_ACTIVITY_PATH, AUTH_STATUS_PATH,
            AUTH_SETUP_PATH, AUTH_LOGIN_PATH,
            OIDC_START_PATH, OIDC_CALLBACK_PATH, OIDC_EXCHANGE_PATH, AboutRoutes.ABOUT_PATH);
    /** Seules routes permises tant qu'un mot de passe provisoire n'a pas été changé. */
    private static final Set<String> PASSWORD_CHANGE_PATHS = Set.of(AUTH_ME_PATH, AUTH_PASSWORD_PATH, AUTH_LOGOUT_PATH);
    private static final String CONTENT_SECURITY_POLICY = "default-src 'self'; img-src 'self' data:; "
            + "style-src 'self' 'unsafe-inline'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'";

    /**
     * Services exposés par l'API.
     *
     * @param trustProxy utiliser X-Forwarded-For pour l'adresse d'origine (derrière un proxy de confiance)
     */
    public record Dependencies(AnalysisService analyses, CatalogService catalog, AnalysisRepository repository,
                               AuthService auth, SsoService sso, UserService users, AuditService audit,
                               AuditArchiveService auditArchive, SettingsService settings, RetentionService retention, GroupService groups,
                               CatalogRequestService catalogRequests, NotificationService notifications,
                               AccountService account, Map<String, Object> info,
                               Map<String, Object> about, Supplier<List<String>> externalServices,
                               ObjectMapper mapper, Clock clock, boolean trustProxy,
                               Optional<String> desktopControlToken) {
    }

    private final Dependencies deps;
    private Javalin app;

    public ApiServer(Dependencies deps) {
        this.deps = deps;
    }

    public ApiServer start(String host, int port, Optional<Path> staticDir, List<String> corsOrigins) {
        app = Javalin.create(config -> {
            config.showJavalinBanner = false;
            config.jsonMapper(new JavalinJackson(deps.mapper(), false));
            config.http.maxRequestSize = MAX_REQUEST_BYTES;
            if (deps.trustProxy()) {
                config.contextResolver.ip = ApiServer::forwardedIp;
            }
            config.requestLogger.http((ctx, ms) -> {
                if (!ctx.path().equals(HEALTH_PATH)) {
                    LOG.info("{} {} -> {} ({} ms)", ctx.method(), ctx.path(), ctx.status().getCode(), Math.round(ms));
                }
            });
            staticDir.ifPresent(dir -> config.staticFiles.add(files -> {
                files.hostedPath = "/";
                files.directory = dir.toAbsolutePath().toString();
                files.location = Location.EXTERNAL;
                // Revalidation systématique (ETag) : après une mise à jour, aucun ancien module JS n'est réutilisé.
                files.headers = Map.of("Cache-Control", "no-cache");
            }));
            if (!corsOrigins.isEmpty()) {
                config.bundledPlugins.enableCors(cors -> cors.addRule(rule -> corsOrigins.forEach(rule::allowHost)));
            }
        });
        app.before(ApiServer::securityHeaders);
        app.before("/api/*", this::authenticate);
        // La version permet aux interfaces ouvertes de proposer un rechargement après une mise à jour du serveur.
        app.get(HEALTH_PATH, ctx -> ctx.json(Map.of("status", "UP", "version", deps.info().getOrDefault("version", "dev"))));
        deps.desktopControlToken().ifPresent(token -> app.get(DESKTOP_ACTIVITY_PATH, ctx -> {
            // Canal privé de l'application de bureau (jeton aléatoire transmis au démarrage du moteur).
            String presented = ctx.header(DESKTOP_TOKEN_HEADER);
            if (presented == null || !MessageDigest.isEqual(presented.getBytes(StandardCharsets.UTF_8),
                    token.getBytes(StandardCharsets.UTF_8))) {
                throw new ApiServer.NotFound("Ressource introuvable");
            }
            ctx.json(deps.analyses().activity());
        }));
        new AuthRoutes(deps.auth(), deps.sso(), new LoginThrottle(deps.clock())).register(app);
        new AnalysisRoutes(deps.analyses(), deps.repository(), deps.audit(), deps.info()).register(app);
        new CatalogRoutes(deps.catalog(), deps.audit()).register(app);
        new AdminRoutes(deps.users(), deps.audit(), deps.auditArchive(), deps.settings(), deps.retention(),
                deps.analyses(), deps.catalogRequests(), deps.groups(), deps.notifications()).register(app);
        new CollaborationRoutes(deps.groups(), deps.catalogRequests(), deps.notifications(), deps.account())
                .register(app);
        new AboutRoutes(deps.about(), deps.settings()::current, deps.externalServices()).register(app);
        registerErrors(app);
        app.start(host, port);
        return this;
    }

    public void stop() {
        if (app != null) {
            app.stop();
        }
    }

    public int port() {
        return app.port();
    }

    private static void securityHeaders(Context ctx) {
        ctx.header("X-Content-Type-Options", "nosniff");
        ctx.header("X-Frame-Options", "DENY");
        ctx.header("Referrer-Policy", "no-referrer");
        ctx.header("Content-Security-Policy", CONTENT_SECURITY_POLICY);
        if (ctx.path().startsWith("/api/")) {
            ctx.header("Cache-Control", "no-store");
        }
    }

    private void authenticate(Context ctx) {
        if (ctx.method() == HandlerType.OPTIONS || PUBLIC_PATHS.contains(ctx.path())) {
            return;
        }
        AuthenticatedSession session = deps.auth().authenticate(RequestContext.bearerToken(ctx),
                RequestContext.sourceIp(ctx));
        if (session.user().mustChangePassword() && !PASSWORD_CHANGE_PATHS.contains(ctx.path())) {
            throw new PasswordChangeRequired();
        }
        RequestContext.attach(ctx, session);
    }

    private static String forwardedIp(Context ctx) {
        String forwarded = ctx.header(FORWARDED_FOR);
        if (forwarded == null || forwarded.isBlank()) {
            return ctx.req().getRemoteAddr();
        }
        return forwarded.split(",")[0].trim();
    }

    private void registerErrors(Javalin server) {
        server.exception(NotFound.class, (e, ctx) -> error(ctx, HttpStatus.NOT_FOUND, e.getMessage(), null, null));
        server.exception(AuthenticationException.class,
                (e, ctx) -> error(ctx, HttpStatus.UNAUTHORIZED, e.getMessage(), null, "AUTHENTICATION_REQUIRED"));
        server.exception(PasswordChangeRequired.class,
                (e, ctx) -> error(ctx, HttpStatus.FORBIDDEN, e.getMessage(), null, "PASSWORD_CHANGE_REQUIRED"));
        server.exception(AccessDeniedException.class,
                (e, ctx) -> error(ctx, HttpStatus.FORBIDDEN, e.getMessage(), null, "FORBIDDEN"));
        server.exception(TooManyAttempts.class,
                (e, ctx) -> error(ctx, HttpStatus.TOO_MANY_REQUESTS, e.getMessage(), null, null));
        server.exception(IllegalArgumentException.class,
                (e, ctx) -> error(ctx, HttpStatus.BAD_REQUEST, e.getMessage(), null, null));
        server.exception(io.javalin.http.BadRequestResponse.class,
                (e, ctx) -> error(ctx, HttpStatus.BAD_REQUEST, "Requête invalide : " + e.getMessage(), null, null));
        server.exception(com.fasterxml.jackson.core.JacksonException.class, (e, ctx) ->
                error(ctx, HttpStatus.BAD_REQUEST, "Corps JSON invalide : " + e.getOriginalMessage(), null, null));
        server.exception(AnalysisService.QueueFullException.class,
                (e, ctx) -> error(ctx, HttpStatus.TOO_MANY_REQUESTS, e.getMessage(), null, null));
        server.exception(AnalysisException.class,
                (e, ctx) -> error(ctx, HttpStatus.CONFLICT, e.getMessage(), null, null));
        server.exception(Misconfigured.class,
                (e, ctx) -> error(ctx, HttpStatus.CONFLICT, e.getMessage(), null, "MISCONFIGURED"));
        server.exception(CatalogService.InvalidCatalogException.class,
                (e, ctx) -> error(ctx, HttpStatus.UNPROCESSABLE_CONTENT, "Catalogue invalide", e.errors(), null));
        server.exception(Exception.class, (e, ctx) -> {
            LOG.error("Erreur inattendue sur {} {}", ctx.method(), ctx.path(), e);
            error(ctx, HttpStatus.INTERNAL_SERVER_ERROR, "Erreur interne du serveur.", null, null);
        });
    }

    private static void error(Context ctx, HttpStatus status, String message, List<String> details, String code) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("error", message);
        if (code != null) {
            body.put("code", code);
        }
        if (details != null) {
            body.put("details", details);
        }
        ctx.status(status).json(body);
    }

    /**
     * La demande est valide, mais la configuration du serveur ne permet pas de la satisfaire (409). Le
     * message est destiné à l'administrateur : il doit dire quoi corriger, pas "erreur interne".
     */
    static final class Misconfigured extends RuntimeException {
        private static final long serialVersionUID = 1L;

        Misconfigured(String message) {
            super(message);
        }
    }

    /** Ressource absente (404). */
    static final class NotFound extends RuntimeException {
        private static final long serialVersionUID = 1L;

        NotFound(String message) {
            super(message);
        }
    }

    /** Trop de tentatives d'authentification (429). */
    static final class TooManyAttempts extends RuntimeException {
        private static final long serialVersionUID = 1L;

        TooManyAttempts(String message) {
            super(message);
        }
    }

    /** Mot de passe provisoire à changer avant toute autre action (403). */
    static final class PasswordChangeRequired extends RuntimeException {
        private static final long serialVersionUID = 1L;

        PasswordChangeRequired() {
            super("Changement du mot de passe provisoire requis.");
        }
    }
}
