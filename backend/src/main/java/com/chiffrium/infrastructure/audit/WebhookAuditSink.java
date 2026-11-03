package com.chiffrium.infrastructure.audit;

import com.chiffrium.application.port.AuditSink;
import com.chiffrium.domain.security.AuditEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.time.Duration;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Archivage vers un collecteur https (SIEM, fonction serverless...). Le corps est signé en HMAC-SHA256 avec le
 * secret partagé (en-tête {@value #SIGNATURE_HEADER} : {@code sha256=<hex>}) pour que le destinataire rejette
 * tout envoi falsifié.
 */
public final class WebhookAuditSink implements AuditSink {

    static final String SIGNATURE_HEADER = "X-Chiffrium-Signature";
    private static final String HMAC = "HmacSHA256";
    private static final int SUCCESS_MIN = 200;
    private static final int SUCCESS_MAX = 299;

    private final URI url;
    private final String secret;
    private final ObjectMapper mapper;
    private final HttpClient client;
    private final Duration timeout;

    public WebhookAuditSink(String url, String secret, ObjectMapper mapper, Duration timeout) {
        this.url = URI.create(url);
        this.secret = secret;
        this.mapper = mapper;
        this.timeout = timeout;
        this.client = HttpClient.newBuilder().connectTimeout(timeout).followRedirects(HttpClient.Redirect.NEVER).build();
    }

    @Override
    public String name() {
        return "webhook " + url.getHost();
    }

    @Override
    public void publish(List<AuditEvent> events) {
        AuditEvent last = events.get(events.size() - 1);
        byte[] body;
        try {
            body = mapper.writeValueAsBytes(Map.of("events", events,
                    "anchor", Map.of("sequence", last.sequence(), "hash", last.hash())));
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("Lot d'audit non sérialisable", e);
        }
        HttpRequest.Builder request = HttpRequest.newBuilder(url).timeout(timeout)
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofByteArray(body));
        if (secret != null) {
            request.header(SIGNATURE_HEADER, "sha256=" + sign(body));
        }
        try {
            HttpResponse<Void> response = client.send(request.build(), HttpResponse.BodyHandlers.discarding());
            if (response.statusCode() < SUCCESS_MIN || response.statusCode() > SUCCESS_MAX) {
                throw new IllegalStateException("réponse HTTP " + response.statusCode());
            }
        } catch (IOException e) {
            throw new IllegalStateException("collecteur injoignable : " + e.getMessage(), e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("envoi interrompu", e);
        }
    }

    String sign(byte[] body) {
        try {
            Mac mac = Mac.getInstance(HMAC);
            mac.init(new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), HMAC));
            return HexFormat.of().formatHex(mac.doFinal(body));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(HMAC + " indisponible", e);
        }
    }
}
