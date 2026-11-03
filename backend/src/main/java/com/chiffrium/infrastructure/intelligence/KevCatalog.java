package com.chiffrium.infrastructure.intelligence;

import com.fasterxml.jackson.databind.JsonNode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.HashSet;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * Catalogue CISA "Known Exploited Vulnerabilities" : CVE exploitées activement, à corriger en priorité.
 * Le flux (environ 1 Mo) est mis en cache sur disque et rafraîchi au plus une fois par période ; en cas
 * d'indisponibilité, la dernière copie est utilisée (fonctionnement hors ligne).
 */
final class KevCatalog {

    private static final Logger LOG = LoggerFactory.getLogger(KevCatalog.class);
    private static final String CACHE_FILE = "kev.json";

    private final HttpJson http;
    private final String url;
    private final Path cacheDir;
    private final Duration refreshPeriod;
    private final Clock clock;
    private volatile Set<String> cves;
    private volatile Instant loadedAt;

    KevCatalog(HttpJson http, String url, Path cacheDir, Duration refreshPeriod, Clock clock) {
        this.http = http;
        this.url = url;
        this.cacheDir = cacheDir;
        this.refreshPeriod = refreshPeriod;
        this.clock = clock;
    }

    synchronized Set<String> exploitedCves() {
        Instant now = clock.instant();
        if (cves != null && loadedAt.plus(refreshPeriod).isAfter(now)) {
            return cves;
        }
        Path cache = cacheDir.resolve(CACHE_FILE);
        byte[] body = freshCache(cache, now).orElseGet(() -> download(cache).orElseGet(() -> staleCache(cache)));
        cves = body == null ? Set.of() : parse(body);
        loadedAt = now;
        return cves;
    }

    private Optional<byte[]> freshCache(Path cache, Instant now) {
        try {
            if (Files.exists(cache) && Files.getLastModifiedTime(cache).toInstant().plus(refreshPeriod).isAfter(now)) {
                return Optional.of(Files.readAllBytes(cache));
            }
        } catch (IOException e) {
            LOG.debug("Cache KEV illisible", e);
        }
        return Optional.empty();
    }

    private Optional<byte[]> download(Path cache) {
        Optional<byte[]> body = http.getBytes(url, Map.of());
        body.ifPresent(bytes -> {
            try {
                Files.createDirectories(cacheDir);
                Files.write(cache, bytes);
            } catch (IOException e) {
                LOG.warn("Mise en cache du catalogue KEV impossible", e);
            }
        });
        return body;
    }

    private byte[] staleCache(Path cache) {
        try {
            if (Files.exists(cache)) {
                LOG.warn("Catalogue KEV injoignable : utilisation de la copie locale du {}",
                        Files.getLastModifiedTime(cache));
                return Files.readAllBytes(cache);
            }
        } catch (IOException e) {
            LOG.debug("Cache KEV illisible", e);
        }
        LOG.warn("Catalogue KEV indisponible : enrichissement ignoré");
        return null;
    }

    private Set<String> parse(byte[] body) {
        Set<String> result = new HashSet<>();
        http.parse(body).map(root -> root.path("vulnerabilities")).ifPresent(list -> {
            for (JsonNode entry : list) {
                String cve = entry.path("cveID").asText(null);
                if (cve != null) {
                    result.add(cve);
                }
            }
        });
        return Set.copyOf(result);
    }
}
