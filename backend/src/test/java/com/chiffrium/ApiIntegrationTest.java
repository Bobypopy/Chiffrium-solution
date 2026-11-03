package com.chiffrium;

import com.chiffrium.api.ApiServer;
import com.chiffrium.infrastructure.config.AppConfig;
import com.fasterxml.jackson.databind.JsonNode;
import org.eclipse.jgit.api.Git;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Test de bout en bout : API HTTP réelle, pipeline réel (sans cdxgen ni réseau) sur un vrai projet Java.
 */
class ApiIntegrationTest {

    private static final Duration ANALYSIS_TIMEOUT = Duration.ofSeconds(60);
    private static final long POLL_MILLIS = 200;
    private static final String LOOPBACK = "127.0.0.1";
    private static final String DESKTOP_TOKEN = "jeton-du-bureau-pour-les-tests";

    @TempDir
    static Path dataDir;
    private static ApiServer server;
    private static Main.Application application;
    private static final HttpClient HTTP = HttpClient.newHttpClient();
    private static String base;
    private static String adminToken;
    private static final String ADMIN_PASSWORD = "phrase de passe du test";

    @BeforeAll
    static void start() throws IOException {
        Path projects = TestSupport.fixture("projects");
        Path repositories = Files.createDirectories(dataDir.resolve("depots"));
        application = new Main.Application(AppConfig.from(Map.of(
                "DATA_DIR", dataDir.toString(),
                "ALLOWED_LOCAL_ROOTS", projects + "," + repositories,
                "OSV_ENABLED", "false",
                "CDXGEN_COMMAND", "cdxgen-absent-pour-les-tests")));
        server = new ApiServer(new ApiServer.Dependencies(application.analysisService, application.catalogService,
                application.repository, application.auth, application.sso, application.users, application.audit,
                application.auditArchive, application.settings, application.retention, application.groups, application.catalogRequests,
                application.notifications, application.account, application.info(),
                application.about(), application::externalServices, application.mapper, application.clock, false,
                Optional.of(DESKTOP_TOKEN)))
                .start(LOOPBACK, 0, Optional.empty(), List.of());
        base = "http://" + LOOPBACK + ":" + server.port();
        adminToken = setupAdmin();
    }

    private static String setupAdmin() {
        try {
            String setupToken = application.setupTokens.current().orElseThrow();
            HttpResponse<String> response = send("POST", "/api/auth/setup", "{\"setupToken\":\"" + setupToken
                    + "\",\"username\":\"admin\",\"password\":\"" + ADMIN_PASSWORD + "\"}", null);
            assertThat(response.statusCode()).as(response.body()).isEqualTo(201);
            return json(response).path("token").asText();
        } catch (IOException e) {
            throw new java.io.UncheckedIOException(e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException(e);
        }
    }

    @AfterAll
    static void stop() {
        server.stop();
        application.analysisService.close();
        application.database.close();
    }

    private static HttpResponse<String> send(String method, String path, String body) throws IOException, InterruptedException {
        return send(method, path, body, adminToken);
    }

    private static HttpResponse<String> send(String method, String path, String body, String token)
            throws IOException, InterruptedException {
        HttpRequest.Builder builder = HttpRequest.newBuilder(URI.create(base + path)).header("Content-Type", "application/json");
        if (token != null) {
            builder.header("Authorization", "Bearer " + token);
        }
        builder.method(method, body == null ? HttpRequest.BodyPublishers.noBody() : HttpRequest.BodyPublishers.ofString(body));
        return HTTP.send(builder.build(), HttpResponse.BodyHandlers.ofString());
    }

    private static JsonNode json(HttpResponse<String> response) throws IOException {
        return TestSupport.MAPPER.readTree(response.body());
    }

    @Test
    void fullAnalysisOfARealJavaProject() throws Exception {
        String target = TestSupport.fixture("projects/java-crypto-package").toString().replace("\\", "\\\\");
        HttpResponse<String> submitted = send("POST", "/api/analyses",
                "{\"target\":\"" + target + "\",\"runCdxgen\":false,\"scanVulnerabilities\":false}");
        assertThat(submitted.statusCode()).isEqualTo(202);
        String id = json(submitted).get(0).path("id").asText();

        JsonNode job = waitForCompletion(id);
        assertThat(job.path("status").asText()).as(job.toString()).isEqualTo("succeeded");
        assertThat(job.path("steps").toString()).contains("détection règles").contains("\"skipped\"");

        JsonNode report = json(send("GET", "/api/analyses/" + id + "/report", null));
        assertThat(report.path("schemaVersion").asInt()).isEqualTo(3);
        assertThat(report.path("summary").path("pqc").path("stage").asText()).isEqualTo("not-started");
        assertThat(report.has("findings")).isTrue();
        List<String> names = new ArrayList<>();
        report.path("assets").forEach(a -> names.add(a.path("name").asText()));
        // Cipher.getInstance("AES") vaut AES/ECB/PKCS5Padding et "RSA" vaut RSA/ECB/PKCS1Padding en Java.
        assertThat(names).contains("AES-GCM-NoPadding", "AES-ECB-PKCS7", "RSA-PKCS1-v1.5", "PBKDF2-HMAC-SHA-256",
                "RSA-2048", "AES-256");
        assertThat(report.path("summary").path("byStatus").path("disallowed").asInt()).isPositive();
        assertThat(report.path("callGraph").path("edges").toString()).contains("produces", "consumes");

        HttpResponse<String> cbom = send("GET", "/api/analyses/" + id + "/cbom", null);
        assertThat(cbom.statusCode()).isEqualTo(200);
        assertThat(cbom.headers().firstValue("Content-Disposition")).get().asString().contains("attachment");
        assertThat(json(cbom).path("specVersion").asText()).isEqualTo("1.6");

        assertThat(send("GET", "/api/analyses/" + id + "/log", null).body()).contains("Étape");
        HttpResponse<String> sarif = send("GET", "/api/analyses/" + id + "/sarif", null);
        assertThat(sarif.statusCode()).isEqualTo(200);
        assertThat(json(sarif).path("version").asText()).isEqualTo("2.1.0");
        assertThat(json(sarif).path("runs").get(0).path("results").size()).isPositive();
        assertThat(json(send("GET", "/api/analyses", null)).toString()).contains(id);

        assertThat(send("DELETE", "/api/analyses/" + id, null).statusCode()).isEqualTo(204);
        assertThat(send("GET", "/api/analyses/" + id, null).statusCode()).isEqualTo(404);
    }

    @Test
    void gitHistoryOptionReportsSecretsRemovedFromTheCode() throws Exception {
        Path repo = Files.createDirectories(dataDir.resolve("depots/historique"));
        try (Git git = Git.init().setDirectory(repo.toFile()).call()) {
            TestSupport.write(repo, "app.properties", "db.password=Hx7kQ2mP9vLr\napi.secret=Zq8vR2pL9wXk\n");
            git.add().addFilepattern(".").call();
            git.commit().setMessage("v1").setAuthor("t", "t@example.org").setCommitter("t", "t@example.org")
                    .setSign(false).call();
            TestSupport.write(repo, "app.properties", "db.password=${DB_PASSWORD}\napi.secret=Zq8vR2pL9wXk\n");
            git.add().addFilepattern(".").call();
            git.commit().setMessage("v2").setAuthor("t", "t@example.org").setCommitter("t", "t@example.org")
                    .setSign(false).call();
        }
        String target = repo.toString().replace("\\", "\\\\");

        JsonNode withHistory = analyzedReport("{\"target\":\"" + target
                + "\",\"runCdxgen\":false,\"scanVulnerabilities\":false,\"scanGitHistory\":true}");
        List<JsonNode> secrets = new ArrayList<>();
        withHistory.path("findings").forEach(f -> {
            if ("secret-config-assignment".equals(f.path("ruleId").asText())) {
                secrets.add(f);
            }
        });
        // Le mot de passe retiré vient de l'historique ; le secret toujours présent n'est signalé qu'une fois.
        assertThat(secrets).hasSize(2);
        assertThat(secrets).filteredOn(f -> f.hasNonNull("commit")).singleElement()
                .satisfies(f -> assertThat(f.path("evidence").asText()).startsWith("Hx7k"));

        JsonNode withoutHistory = analyzedReport("{\"target\":\"" + target
                + "\",\"runCdxgen\":false,\"scanVulnerabilities\":false}");
        assertThat(withoutHistory.path("findings").toString()).doesNotContain("\"commit\"");
    }

    private JsonNode analyzedReport(String submission) throws Exception {
        HttpResponse<String> submitted = send("POST", "/api/analyses", submission);
        assertThat(submitted.statusCode()).as(submitted.body()).isEqualTo(202);
        String id = json(submitted).get(0).path("id").asText();
        JsonNode job = waitForCompletion(id);
        assertThat(job.path("status").asText()).as(job.toString()).isEqualTo("succeeded");
        return json(send("GET", "/api/analyses/" + id + "/report", null));
    }

    @Test
    void desktopActivityChannelRequiresTheLaunchToken() throws Exception {
        assertThat(send("GET", "/api/desktop/activity", null, null).statusCode()).isEqualTo(404);
        assertThat(send("GET", "/api/desktop/activity", null).statusCode()).as("une session ne suffit pas").isEqualTo(404);
        HttpResponse<String> activity = HTTP.send(HttpRequest.newBuilder(URI.create(base + "/api/desktop/activity"))
                .header("X-Desktop-Token", DESKTOP_TOKEN).build(), HttpResponse.BodyHandlers.ofString());
        assertThat(activity.statusCode()).isEqualTo(200);
        assertThat(json(activity).has("running")).isTrue();
        assertThat(json(activity).has("queued")).isTrue();
    }

    @Test
    void forbiddenTargetsFailWithClearMessage() throws Exception {
        HttpResponse<String> submitted = send("POST", "/api/analyses", "{\"target\":\"C:/Windows\",\"runCdxgen\":false}");
        String id = json(submitted).get(0).path("id").asText();
        JsonNode job = waitForCompletion(id);
        assertThat(job.path("status").asText()).isEqualTo("failed");
        assertThat(job.path("error").asText()).containsAnyOf("hors des racines", "introuvable");
    }

    @Test
    void validatesRequests() throws Exception {
        assertThat(send("POST", "/api/analyses", "{}").statusCode()).isEqualTo(400);
        assertThat(send("POST", "/api/analyses", "not json").statusCode()).isEqualTo(400);
        assertThat(send("GET", "/api/analyses/../../etc/passwd", null).statusCode()).isEqualTo(404);
        assertThat(send("GET", "/api/analyses/00000000-0000-0000-0000-000000000000", null).statusCode()).isEqualTo(404);
        assertThat(send("PUT", "/api/catalog/algorithms/aes", "{\"id\":\"other\"}").statusCode()).isEqualTo(400);
    }

    @Test
    void exposesInfoHealthAndCatalog() throws Exception {
        assertThat(json(send("GET", "/api/health", null)).path("status").asText()).isEqualTo("UP");
        assertThat(json(send("GET", "/api/health", null, null)).has("version")).isTrue();
        JsonNode info = json(send("GET", "/api/info", null));
        assertThat(info.path("cdxgenVersion").asText()).isEqualTo("indisponible");
        assertThat(info.path("ruleLanguages").toString()).contains("go", "csharp", "rust");
        assertThat(json(send("GET", "/api/catalog", null)).path("algorithms").size()).isGreaterThan(80);
        assertThat(json(send("GET", "/api/catalog/reference-oids", null)).toString())
                .as("OID proposés à la saisie").contains("1.2.840.113549.2.9", "hmac");
    }

    @Test
    void requiresAuthenticationAndEnforcesRoles() throws Exception {
        assertThat(send("GET", "/api/analyses", null, null).statusCode()).isEqualTo(401);
        assertThat(send("GET", "/api/analyses", null, "jeton-invalide").statusCode()).isEqualTo(401);
        assertThat(json(send("GET", "/api/auth/status", null, null)).path("setupRequired").asBoolean()).isFalse();
        assertThat(send("GET", "/api/health", null, null).headers().firstValue("X-Frame-Options")).contains("DENY");

        JsonNode created = json(send("POST", "/api/admin/users", "{\"username\":\"viewer1\",\"role\":\"viewer\"}"));
        String temporary = created.path("temporaryPassword").asText();
        String viewerToken = json(send("POST", "/api/auth/login",
                "{\"username\":\"viewer1\",\"password\":\"" + temporary + "\"}", null)).path("token").asText();

        HttpResponse<String> blocked = send("GET", "/api/analyses", null, viewerToken);
        assertThat(blocked.statusCode()).isEqualTo(403);
        assertThat(json(blocked).path("code").asText()).isEqualTo("PASSWORD_CHANGE_REQUIRED");

        HttpResponse<String> changed = send("POST", "/api/auth/change-password", "{\"currentPassword\":\"" + temporary
                + "\",\"newPassword\":\"lecteur phrase secrète\"}", viewerToken);
        assertThat(changed.statusCode()).as(changed.body()).isEqualTo(200);
        String renewed = json(changed).path("token").asText();

        assertThat(send("GET", "/api/analyses", null, renewed).statusCode()).isEqualTo(200);
        assertThat(send("POST", "/api/analyses", "{\"target\":\"x\"}", renewed).statusCode()).isEqualTo(403);
        assertThat(send("GET", "/api/admin/users", null, renewed).statusCode()).isEqualTo(403);
        assertThat(send("PUT", "/api/catalog/algorithms/aes", "{\"id\":\"aes\"}", renewed).statusCode()).isEqualTo(403);
    }

    @Test
    void adminSeesAnIntactAuditTrailAndMaskedSettings() throws Exception {
        assertThat(send("POST", "/api/auth/login", "{\"username\":\"admin\",\"password\":\"faux mot de passe\"}", null)
                .statusCode()).isEqualTo(401);
        JsonNode verification = json(send("GET", "/api/admin/audit/verify", null));
        assertThat(verification.path("intact").asBoolean()).isTrue();
        assertThat(json(send("GET", "/api/admin/audit?action=LOGIN_FAILURE", null)).size()).isPositive();

        HttpResponse<String> updated = send("PUT", "/api/admin/settings",
                "{\"intelligence\":{\"osv\":false,\"kev\":true,\"epss\":true,\"nvd\":true,\"nvdApiKey\":\"abc-secret\"}}");
        assertThat(updated.statusCode()).as(updated.body()).isEqualTo(200);
        assertThat(updated.body()).doesNotContain("abc-secret").contains("********");
        assertThat(json(send("GET", "/api/admin/storage", null)).has("usedBytes")).isTrue();
    }

    @Test
    void teamFeaturesGroupsFavoritesComparisonAndRequests() throws Exception {
        String target = TestSupport.fixture("projects/java-crypto-package").toString().replace("\\", "\\\\");
        HttpResponse<String> createdGroup = send("POST", "/api/groups", "{\"name\":\"Équipe API\",\"visibility\":\"public\"}");
        assertThat(createdGroup.statusCode()).as(createdGroup.body()).isEqualTo(201);
        String groupId = json(createdGroup).path("id").asText();
        assertThat(json(send("GET", "/api/me/groups", null)).toString()).as("le créateur est responsable")
                .contains(groupId).contains("\"manager\":true");
        send("POST", "/api/admin/users", "{\"username\":\"invitee\",\"role\":\"viewer\"}");
        HttpResponse<String> invitation = send("POST", "/api/groups/" + groupId + "/invitations",
                "{\"username\":\"invitee\"}");
        assertThat(invitation.statusCode()).as(invitation.body()).isEqualTo(201);
        assertThat(json(invitation).path("status").asText()).isEqualTo("pending");
        assertThat(send("POST", "/api/invitations/" + json(invitation).path("id").asText() + "/accept", null)
                .statusCode()).as("seul l'invité peut accepter").isEqualTo(403);

        String body = "{\"target\":\"" + target + "\",\"runCdxgen\":false,\"scanVulnerabilities\":false,\"groupId\":\""
                + groupId + "\"}";
        String first = json(send("POST", "/api/analyses", body)).get(0).path("id").asText();
        waitForCompletion(first);
        String second = json(send("POST", "/api/analyses", body)).get(0).path("id").asText();
        waitForCompletion(second);
        assertThat(json(send("GET", "/api/analyses/" + first, null)).path("groupId").asText()).isEqualTo(groupId);

        assertThat(json(send("PUT", "/api/analyses/" + first + "/label", "{\"label\":\"Version 1.0\"}"))
                .path("label").asText()).isEqualTo("Version 1.0");
        HttpResponse<String> bundle = send("GET", "/api/analyses/" + first + "/bundle", null);
        assertThat(bundle.statusCode()).isEqualTo(200);
        assertThat(bundle.headers().firstValue("Content-Disposition").orElseThrow())
                .matches("attachment; filename=\"chiffrium-Version-1.0-\\d{4}-\\d{2}-\\d{2}\\.zip\"");
        assertThat(send("GET", "/api/analyses/" + first + "/log?download=true", null).headers()
                .firstValue("Content-Disposition").orElseThrow()).contains("journal-Version-1.0-").endsWith(".log\"");
        assertThat(send("GET", "/api/analyses/" + first + "/log", null).headers()
                .firstValue("Content-Disposition")).as("affichage dans l'interface").isEmpty();
        assertThat(json(send("GET", "/api/notifications/count", null)).path("unread").asLong()).isPositive();
        JsonNode overview = json(send("GET", "/api/admin/overview", null));
        assertThat(overview.path("groups").asInt()).isPositive();
        assertThat(overview.path("auditIntact").asBoolean()).isTrue();
        assertThat(send("PUT", "/api/analyses/" + first + "/favorite", null).statusCode()).isEqualTo(204);
        assertThat(json(send("GET", "/api/favorites", null)).toString()).contains(first);

        JsonNode diff = json(send("GET", "/api/analyses/" + first + "/compare/" + second, null));
        assertThat(diff.path("assetsAdded").size()).isZero();
        assertThat(diff.path("findingsNew").size()).isZero();
        assertThat(diff.has("scoreDelta")).isTrue();
        assertThat(diff.path("scoreDelta").asInt()).isZero();

        HttpResponse<String> request = send("POST", "/api/catalog/requests",
                "{\"kind\":\"delete\",\"algorithmId\":\"md5\",\"justification\":\"Test\"}");
        assertThat(request.statusCode()).as(request.body()).isEqualTo(201);
        String requestId = json(request).path("id").asText();
        assertThat(json(send("POST", "/api/catalog/requests/" + requestId + "/review",
                "{\"approve\":false,\"comment\":\"Pas maintenant\"}")).path("status").asText()).isEqualTo("rejected");

        JsonNode about = json(send("GET", "/api/about", null, null));
        assertThat(about.path("license").asText()).contains("propriétaire");
        assertThat(about.path("thirdParty").path("components").size()).isPositive();
    }

    private static JsonNode waitForCompletion(String id) throws Exception {
        Instant deadline = Instant.now().plus(ANALYSIS_TIMEOUT);
        while (Instant.now().isBefore(deadline)) {
            JsonNode job = json(send("GET", "/api/analyses/" + id, null));
            String status = job.path("status").asText();
            if ("succeeded".equals(status) || "failed".equals(status)) {
                return job;
            }
            Thread.sleep(POLL_MILLIS);
        }
        throw new AssertionError("Analyse non terminée dans le délai : " + id);
    }
}
