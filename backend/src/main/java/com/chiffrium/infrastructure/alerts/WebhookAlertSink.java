package com.chiffrium.infrastructure.alerts;

import com.chiffrium.application.port.AlertSink;
import com.chiffrium.application.settings.Settings.Alerts.Format;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Relais des alertes vers un webhook entrant gratuit : Slack / Mattermost / Rocket.Chat, Discord, Microsoft
 * Teams (flux Workflows) ou collecteur générique.
 */
public final class WebhookAlertSink implements AlertSink {

    private static final int SUCCESS_MIN = 200;
    private static final int SUCCESS_MAX = 299;
    private static final String PRODUCT = "Chiffrium";

    private final URI url;
    private final Format format;
    private final ObjectMapper mapper;
    private final HttpClient client;
    private final Duration timeout;

    public WebhookAlertSink(String url, Format format, ObjectMapper mapper, Duration timeout) {
        this.url = URI.create(url);
        this.format = format == null ? Format.GENERIC : format;
        this.mapper = mapper;
        this.timeout = timeout;
        this.client = HttpClient.newBuilder().connectTimeout(timeout).followRedirects(HttpClient.Redirect.NEVER).build();
    }

    @Override
    public void send(String title, String body, String link) {
        byte[] payload;
        try {
            payload = mapper.writeValueAsBytes(payload(title, body, link));
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("Alerte non sérialisable", e);
        }
        HttpRequest request = HttpRequest.newBuilder(url).timeout(timeout).header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofByteArray(payload)).build();
        try {
            HttpResponse<Void> response = client.send(request, HttpResponse.BodyHandlers.discarding());
            if (response.statusCode() < SUCCESS_MIN || response.statusCode() > SUCCESS_MAX) {
                throw new IllegalStateException("réponse HTTP " + response.statusCode());
            }
        } catch (IOException e) {
            throw new IllegalStateException("webhook injoignable : " + e.getMessage(), e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("envoi interrompu", e);
        }
    }

    Object payload(String title, String body, String link) {
        String text = "[" + PRODUCT + "] " + title + (body == null ? "" : "\n" + body) + (link == null ? "" : "\n" + link);
        return switch (format) {
            case SLACK -> Map.of("text", text);
            case DISCORD -> Map.of("content", text);
            case TEAMS -> Map.of("type", "message", "attachments", List.of(Map.of(
                    "contentType", "application/vnd.microsoft.card.adaptive",
                    "content", Map.of("type", "AdaptiveCard", "version", "1.4", "body", List.of(
                            Map.of("type", "TextBlock", "text", PRODUCT + " : " + title, "weight", "Bolder",
                                    "wrap", true),
                            Map.of("type", "TextBlock", "text", body == null ? "" : body, "wrap", true))))));
            case GENERIC -> {
                Map<String, Object> generic = new LinkedHashMap<>();
                generic.put("source", PRODUCT);
                generic.put("title", title);
                generic.put("body", body);
                generic.put("link", link);
                yield generic;
            }
        };
    }
}
