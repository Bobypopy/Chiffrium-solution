package com.chiffrium.infrastructure.storage;

import com.chiffrium.application.port.ArtifactStore;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.time.Clock;
import java.time.Duration;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.TreeMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Stockage compatible S3 (MinIO auto-hébergé et gratuit, Garage, Ceph RGW, AWS S3...) avec signature AWS
 * Signature V4 et URL en style "chemin" ({@code endpoint/bucket/clé}), sans dépendance au SDK AWS.
 * Les objets sont déjà chiffrés par l'application (AES-256-GCM) : le stockage ne voit jamais de données en clair.
 */
public final class S3ArtifactStore implements ArtifactStore {

    private static final String ALGORITHM = "AWS4-HMAC-SHA256";
    private static final String SERVICE = "s3";
    private static final String HMAC = "HmacSHA256";
    private static final String SIGNED_HEADERS = "host;x-amz-content-sha256;x-amz-date";
    private static final DateTimeFormatter AMZ_DATE = DateTimeFormatter.ofPattern("yyyyMMdd'T'HHmmss'Z'")
            .withZone(ZoneOffset.UTC);
    private static final DateTimeFormatter AMZ_DAY = DateTimeFormatter.ofPattern("yyyyMMdd").withZone(ZoneOffset.UTC);
    private static final int HTTP_OK_MIN = 200;
    private static final int HTTP_OK_MAX = 299;
    private static final int HTTP_NOT_FOUND = 404;
    private static final Pattern CONTENTS = Pattern.compile("<Contents>(.*?)</Contents>", Pattern.DOTALL);
    private static final Pattern KEY = Pattern.compile("<Key>(.*?)</Key>");
    private static final Pattern SIZE = Pattern.compile("<Size>(\\d+)</Size>");
    private static final Pattern NEXT_TOKEN = Pattern.compile("<NextContinuationToken>(.*?)</NextContinuationToken>");

    /**
     * @param endpoint  URL du service (ex. https://minio.mon-entreprise.fr, http://minio:9000)
     * @param region    région (MinIO : us-east-1 par défaut)
     * @param bucket    compartiment (créé au démarrage s'il n'existe pas)
     * @param accessKey identifiant
     * @param secretKey secret (jamais journalisé)
     */
    public record Config(URI endpoint, String region, String bucket, String accessKey, String secretKey) {
    }

    private final Config config;
    private final HttpClient client;
    private final Duration timeout;
    private final Clock clock;

    public S3ArtifactStore(Config config, Duration timeout, Clock clock) {
        this.config = config;
        this.timeout = timeout;
        this.clock = clock;
        this.client = HttpClient.newBuilder().connectTimeout(timeout).followRedirects(HttpClient.Redirect.NEVER).build();
    }

    /** Crée le compartiment s'il n'existe pas. */
    public S3ArtifactStore ensureBucket() {
        HttpResponse<byte[]> head = send("HEAD", "", Map.of(), new byte[0]);
        if (head.statusCode() == HTTP_NOT_FOUND) {
            check(send("PUT", "", Map.of(), new byte[0]), "création du compartiment");
        } else {
            check(head, "accès au compartiment");
        }
        return this;
    }

    @Override
    public void put(String key, byte[] content) {
        check(send("PUT", key, Map.of(), content), "écriture de " + key);
    }

    @Override
    public Optional<byte[]> get(String key) {
        HttpResponse<byte[]> response = send("GET", key, Map.of(), new byte[0]);
        if (response.statusCode() == HTTP_NOT_FOUND) {
            return Optional.empty();
        }
        check(response, "lecture de " + key);
        return Optional.of(response.body());
    }

    @Override
    public void deletePrefix(String prefix) {
        for (ObjectInfo object : list(prefix)) {
            HttpResponse<byte[]> response = send("DELETE", object.key(), Map.of(), new byte[0]);
            if (response.statusCode() != HTTP_NOT_FOUND) {
                check(response, "suppression de " + object.key());
            }
        }
    }

    @Override
    public long size(String prefix) {
        return list(prefix).stream().mapToLong(ObjectInfo::size).sum();
    }

    record ObjectInfo(String key, long size) {
    }

    List<ObjectInfo> list(String prefix) {
        List<ObjectInfo> objects = new ArrayList<>();
        String token = null;
        do {
            Map<String, String> query = new TreeMap<>(Map.of("list-type", "2", "prefix", prefix));
            if (token != null) {
                query.put("continuation-token", token);
            }
            HttpResponse<byte[]> response = send("GET", "", query, new byte[0]);
            check(response, "liste de " + prefix);
            String xml = new String(response.body(), StandardCharsets.UTF_8);
            Matcher contents = CONTENTS.matcher(xml);
            while (contents.find()) {
                Matcher key = KEY.matcher(contents.group(1));
                Matcher size = SIZE.matcher(contents.group(1));
                if (key.find() && size.find()) {
                    objects.add(new ObjectInfo(unescapeXml(key.group(1)), Long.parseLong(size.group(1))));
                }
            }
            Matcher next = NEXT_TOKEN.matcher(xml);
            token = next.find() ? unescapeXml(next.group(1)) : null;
        } while (token != null);
        return objects;
    }

    private HttpResponse<byte[]> send(String method, String key, Map<String, String> query, byte[] body) {
        String path = "/" + encodePath(config.bucket()) + (key.isEmpty() ? "" : "/" + encodePath(key));
        String canonicalQuery = query.entrySet().stream()
                .map(e -> encode(e.getKey()) + "=" + encode(e.getValue()))
                .sorted()
                .collect(Collectors.joining("&"));
        URI base = config.endpoint();
        URI uri = URI.create(base.getScheme() + "://" + base.getRawAuthority() + path
                + (canonicalQuery.isEmpty() ? "" : "?" + canonicalQuery));
        var now = clock.instant();
        String amzDate = AMZ_DATE.format(now);
        String payloadHash = hex(sha256(body));
        String canonicalRequest = method + "\n" + path + "\n" + canonicalQuery + "\n"
                + "host:" + base.getRawAuthority() + "\n"
                + "x-amz-content-sha256:" + payloadHash + "\n"
                + "x-amz-date:" + amzDate + "\n\n"
                + SIGNED_HEADERS + "\n" + payloadHash;
        String scope = AMZ_DAY.format(now) + "/" + config.region() + "/" + SERVICE + "/aws4_request";
        String stringToSign = ALGORITHM + "\n" + amzDate + "\n" + scope + "\n"
                + hex(sha256(canonicalRequest.getBytes(StandardCharsets.UTF_8)));
        String signature = hex(hmac(signingKey(AMZ_DAY.format(now)), stringToSign));
        HttpRequest.Builder request = HttpRequest.newBuilder(uri).timeout(timeout)
                .header("x-amz-date", amzDate)
                .header("x-amz-content-sha256", payloadHash)
                .header("Authorization", ALGORITHM + " Credential=" + config.accessKey() + "/" + scope
                        + ", SignedHeaders=" + SIGNED_HEADERS + ", Signature=" + signature)
                .method(method, body.length == 0 ? HttpRequest.BodyPublishers.noBody()
                        : HttpRequest.BodyPublishers.ofByteArray(body));
        try {
            return client.send(request.build(), HttpResponse.BodyHandlers.ofByteArray());
        } catch (IOException e) {
            throw new IllegalStateException("Stockage S3 injoignable (" + base.getHost() + ") : " + e.getMessage(), e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("Requête S3 interrompue", e);
        }
    }

    private byte[] signingKey(String day) {
        byte[] date = hmac(("AWS4" + config.secretKey()).getBytes(StandardCharsets.UTF_8), day);
        byte[] region = hmac(date, config.region());
        byte[] service = hmac(region, SERVICE);
        return hmac(service, "aws4_request");
    }

    private static void check(HttpResponse<byte[]> response, String action) {
        if (response.statusCode() < HTTP_OK_MIN || response.statusCode() > HTTP_OK_MAX) {
            throw new IllegalStateException("Stockage S3 : échec de " + action + " (HTTP " + response.statusCode() + ")");
        }
    }

    /** Encodage URI selon AWS : seuls A-Z a-z 0-9 - _ . ~ restent tels quels. */
    static String encode(String value) {
        StringBuilder out = new StringBuilder();
        for (byte b : value.getBytes(StandardCharsets.UTF_8)) {
            char c = (char) (b & 0xff);
            if (Character.isLetterOrDigit(c) && c < 128 || c == '-' || c == '_' || c == '.' || c == '~') {
                out.append(c);
            } else {
                out.append('%').append(String.format("%02X", b & 0xff));
            }
        }
        return out.toString();
    }

    static String encodePath(String path) {
        return Arrays.stream(path.split("/", -1)).map(S3ArtifactStore::encode).collect(Collectors.joining("/"));
    }

    private static String unescapeXml(String value) {
        return value.replace("&lt;", "<").replace("&gt;", ">").replace("&quot;", "\"").replace("&apos;", "'")
                .replace("&amp;", "&");
    }

    private static byte[] sha256(byte[] data) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(data);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    private static byte[] hmac(byte[] key, String data) {
        try {
            Mac mac = Mac.getInstance(HMAC);
            mac.init(new SecretKeySpec(key, HMAC));
            return mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    private static String hex(byte[] bytes) {
        return HexFormat.of().formatHex(bytes);
    }
}
