package com.chiffrium.infrastructure.oidc;

import com.chiffrium.application.port.IdentityProvider;
import com.chiffrium.application.security.AuthenticationException;
import com.chiffrium.application.settings.Settings;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.JWKSourceBuilder;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.text.ParseException;
import java.time.Duration;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

/**
 * Client OpenID Connect : découverte ({@code /.well-known/openid-configuration}), flux "authorization code"
 * avec PKCE S256, et validation complète du jeton ID (signature via le JWKS publié, émetteur, audience,
 * expiration, nonce). Compatible Entra ID, Keycloak, Okta, Google, Auth0, ADFS...
 */
public final class OidcIdentityProvider implements IdentityProvider {

    private static final Logger LOG = LoggerFactory.getLogger(OidcIdentityProvider.class);
    private static final String DISCOVERY_PATH = "/.well-known/openid-configuration";
    private static final String SCOPES = "openid profile email";
    private static final int RANDOM_BYTES = 32;
    private static final int HTTP_OK = 200;
    /** Algorithmes asymétriques acceptés pour le jeton ID (jamais "none" ni HMAC avec le secret client). */
    private static final Set<JWSAlgorithm> ACCEPTED_ALGORITHMS = Set.of(JWSAlgorithm.RS256, JWSAlgorithm.RS384,
            JWSAlgorithm.RS512, JWSAlgorithm.PS256, JWSAlgorithm.PS384, JWSAlgorithm.PS512, JWSAlgorithm.ES256,
            JWSAlgorithm.ES384, JWSAlgorithm.ES512, JWSAlgorithm.EdDSA);

    private record Metadata(String issuer, String authorizationEndpoint, String tokenEndpoint, String jwksUri) {
    }

    private final ObjectMapper mapper;
    private final HttpClient client;
    private final Duration timeout;
    private final SecureRandom random = new SecureRandom();
    private final Map<String, Metadata> metadata = new ConcurrentHashMap<>();
    private final Map<String, JWKSource<SecurityContext>> keySources = new ConcurrentHashMap<>();

    public OidcIdentityProvider(ObjectMapper mapper, Duration timeout) {
        this.mapper = mapper;
        this.timeout = timeout;
        this.client = HttpClient.newBuilder().connectTimeout(timeout).followRedirects(HttpClient.Redirect.NEVER).build();
    }

    @Override
    public AuthorizationRequest authorizationRequest(Settings.Oidc config) {
        Metadata meta = discover(config.issuer());
        String state = randomToken();
        String nonce = randomToken();
        String verifier = randomToken();
        Map<String, String> query = new LinkedHashMap<>();
        query.put("response_type", "code");
        query.put("client_id", config.clientId());
        query.put("redirect_uri", config.redirectUri());
        query.put("scope", SCOPES);
        query.put("state", state);
        query.put("nonce", nonce);
        query.put("code_challenge", challenge(verifier));
        query.put("code_challenge_method", "S256");
        String separator = meta.authorizationEndpoint().contains("?") ? "&" : "?";
        return new AuthorizationRequest(meta.authorizationEndpoint() + separator + form(query), state, nonce, verifier);
    }

    @Override
    public Identity exchange(Settings.Oidc config, String code, String codeVerifier, String expectedNonce) {
        Metadata meta = discover(config.issuer());
        Map<String, String> body = new LinkedHashMap<>();
        body.put("grant_type", "authorization_code");
        body.put("code", code);
        body.put("redirect_uri", config.redirectUri());
        body.put("client_id", config.clientId());
        body.put("code_verifier", codeVerifier);
        if (config.clientSecret() != null) {
            body.put("client_secret", config.clientSecret());
        }
        JsonNode tokens = post(meta.tokenEndpoint(), body);
        String idToken = tokens.path("id_token").asText(null);
        if (idToken == null) {
            throw new AuthenticationException("Le fournisseur n'a pas renvoyé de jeton ID.");
        }
        JWTClaimsSet claims = validate(meta, config, idToken, expectedNonce);
        try {
            return new Identity(claims.getSubject(),
                    firstNonBlank(claims.getStringClaim("preferred_username"), claims.getStringClaim("upn")),
                    claims.getStringClaim("name"), claims.getStringClaim("email"), groups(claims, config.groupsClaim()));
        } catch (ParseException e) {
            throw new AuthenticationException("Revendications du jeton ID illisibles.");
        }
    }

    private JWTClaimsSet validate(Metadata meta, Settings.Oidc config, String idToken, String expectedNonce) {
        DefaultJWTProcessor<SecurityContext> processor = new DefaultJWTProcessor<>();
        processor.setJWSKeySelector(new JWSVerificationKeySelector<>(ACCEPTED_ALGORITHMS,
                keySources.computeIfAbsent(meta.jwksUri(), OidcIdentityProvider::keySource)));
        processor.setJWTClaimsSetVerifier(new DefaultJWTClaimsVerifier<>(config.clientId(),
                new JWTClaimsSet.Builder().issuer(meta.issuer()).claim("nonce", expectedNonce).build(),
                Set.of("sub", "iat", "exp")));
        try {
            return processor.process(idToken, null);
        } catch (ParseException | BadJOSEException | JOSEException e) {
            LOG.warn("Jeton ID refusé : {}", e.getMessage());
            throw new AuthenticationException("Jeton ID invalide.");
        }
    }

    private static JWKSource<SecurityContext> keySource(String jwksUri) {
        try {
            return JWKSourceBuilder.create(URI.create(jwksUri).toURL()).retrying(true).build();
        } catch (IOException | IllegalArgumentException e) {
            throw new AuthenticationException("URL JWKS invalide : " + jwksUri);
        }
    }

    private Metadata discover(String issuer) {
        return metadata.computeIfAbsent(issuer, key -> {
            String base = key.endsWith("/") ? key.substring(0, key.length() - 1) : key;
            JsonNode doc = get(base + DISCOVERY_PATH);
            Metadata meta = new Metadata(doc.path("issuer").asText(null), doc.path("authorization_endpoint").asText(null),
                    doc.path("token_endpoint").asText(null), doc.path("jwks_uri").asText(null));
            if (meta.issuer() == null || meta.authorizationEndpoint() == null || meta.tokenEndpoint() == null
                    || meta.jwksUri() == null) {
                throw new AuthenticationException("Configuration OIDC incomplète chez le fournisseur.");
            }
            if (!stripSlash(meta.issuer()).equals(base)) {
                throw new AuthenticationException("L'émetteur annoncé ne correspond pas à celui configuré.");
            }
            return meta;
        });
    }

    private JsonNode get(String url) {
        return send(HttpRequest.newBuilder(URI.create(url)).timeout(timeout).GET().header("Accept", "application/json")
                .build());
    }

    private JsonNode post(String url, Map<String, String> form) {
        return send(HttpRequest.newBuilder(URI.create(url)).timeout(timeout)
                .header("Content-Type", "application/x-www-form-urlencoded").header("Accept", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(form(form))).build());
    }

    private JsonNode send(HttpRequest request) {
        try {
            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() != HTTP_OK) {
                LOG.warn("Fournisseur OIDC {} : HTTP {}", request.uri().getHost(), response.statusCode());
                throw new AuthenticationException("Le fournisseur d'identité a refusé la requête.");
            }
            return mapper.readTree(response.body());
        } catch (IOException e) {
            throw new AuthenticationException("Fournisseur d'identité injoignable.");
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new AuthenticationException("Connexion SSO interrompue.");
        }
    }

    private static List<String> groups(JWTClaimsSet claims, String claim) {
        Object value = claims.getClaim(claim == null ? "groups" : claim);
        if (value instanceof List<?> list) {
            return list.stream().map(String::valueOf).toList();
        }
        return value == null ? List.of() : List.of(String.valueOf(value));
    }

    private String randomToken() {
        byte[] bytes = new byte[RANDOM_BYTES];
        random.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    static String challenge(String verifier) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(verifier.getBytes(StandardCharsets.US_ASCII));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 indisponible", e);
        }
    }

    private static String form(Map<String, String> values) {
        return values.entrySet().stream()
                .map(e -> URLEncoder.encode(e.getKey(), StandardCharsets.UTF_8) + "="
                        + URLEncoder.encode(e.getValue(), StandardCharsets.UTF_8))
                .collect(Collectors.joining("&"));
    }

    private static String stripSlash(String value) {
        return value.endsWith("/") ? value.substring(0, value.length() - 1) : value;
    }

    private static String firstNonBlank(String first, String second) {
        return first != null && !first.isBlank() ? first : second;
    }
}
