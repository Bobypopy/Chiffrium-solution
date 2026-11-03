package com.chiffrium.infrastructure.intelligence;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Map;
import java.util.Optional;

/**
 * Client HTTP JSON minimal et tolérant : une source de renseignement indisponible ne doit jamais faire
 * échouer une analyse (résultat vide + journalisation).
 */
final class HttpJson {

    private static final Logger LOG = LoggerFactory.getLogger(HttpJson.class);
    private static final int HTTP_OK = 200;

    private final HttpClient client;
    private final ObjectMapper mapper;
    private final Duration timeout;

    HttpJson(ObjectMapper mapper, Duration timeout) {
        this.mapper = mapper;
        this.timeout = timeout;
        this.client = HttpClient.newBuilder().connectTimeout(timeout).followRedirects(HttpClient.Redirect.NORMAL).build();
    }

    Optional<byte[]> getBytes(String url, Map<String, String> headers) {
        try {
            HttpRequest.Builder request = HttpRequest.newBuilder(URI.create(url)).timeout(timeout).GET()
                    .header("Accept", "application/json");
            headers.forEach(request::header);
            HttpResponse<byte[]> response = client.send(request.build(), HttpResponse.BodyHandlers.ofByteArray());
            if (response.statusCode() != HTTP_OK) {
                LOG.warn("{} a répondu {}", hostOf(url), response.statusCode());
                return Optional.empty();
            }
            return Optional.of(response.body());
        } catch (IOException | IllegalArgumentException e) {
            LOG.warn("Source indisponible {} : {}", hostOf(url), e.getMessage());
            return Optional.empty();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return Optional.empty();
        }
    }

    Optional<JsonNode> get(String url, Map<String, String> headers) {
        return getBytes(url, headers).flatMap(this::parse);
    }

    Optional<JsonNode> parse(byte[] body) {
        try {
            return Optional.of(mapper.readTree(body));
        } catch (IOException e) {
            LOG.warn("Réponse JSON invalide : {}", e.getMessage());
            return Optional.empty();
        }
    }

    /** Hôte seul dans les logs : les URL peuvent contenir des paramètres. */
    private static String hostOf(String url) {
        try {
            return URI.create(url).getHost();
        } catch (IllegalArgumentException e) {
            return "?";
        }
    }
}
