package com.chiffrium.infrastructure.config;

import com.chiffrium.domain.model.Language;

import java.nio.file.Path;
import java.time.Duration;
import java.util.Arrays;
import java.util.EnumSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.function.Function;

/**
 * Configuration de l'application, lue exclusivement depuis les variables d'environnement
 * (principe "12-factor" : même image Docker pour tous les environnements, aucun secret dans le code).
 * Chaque valeur a un défaut documenté dans le README et est bornée pour refuser les réglages absurdes.
 */
public record AppConfig(
        int port,
        String bindAddress,
        Path dataDir,
        Optional<String> masterKey,
        Optional<String> databaseUrl,
        String databaseUser,
        Optional<String> databasePassword,
        Optional<Path> auditExportDir,
        String cdxgenCommand,
        Duration cdxgenDefaultTimeout,
        Duration cdxgenMinTimeout,
        Duration cdxgenMaxTimeout,
        Set<Language> cdxgenCryptoLanguages,
        int maxConcurrentAnalyses,
        int maxQueuedAnalyses,
        List<Path> allowedLocalRoots,
        List<String> allowedGitHosts,
        int gitCloneDepth,
        Duration gitTimeout,
        String gitUsername,
        Optional<String> gitToken,
        boolean cdxgenInstallDeps,
        String npmCommand,
        String npmRegistry,
        Duration npmTimeout,
        boolean keepWorkspace,
        boolean osvEnabled,
        String osvUrl,
        Duration osvTimeout,
        String kevUrl,
        String epssUrl,
        String nvdUrl,
        int nvdMaxLookups,
        Duration kevRefresh,
        long maxScannedFileBytes,
        Optional<Path> staticDir,
        List<String> corsOrigins,
        boolean trustProxy,
        boolean exitOnStdinClose,
        ArtifactStorage artifactStorage,
        Optional<String> desktopControlToken) {

    /**
     * Emplacement des artefacts d'analyse.
     * <ul>
     *   <li>{@code LOCAL} : dossier de données de l'instance (bureau, serveur à une réplique) ;</li>
     *   <li>{@code SHARED_DIR} : dossier partagé (NFS, SMB, volume Kubernetes RWX) entre répliques ;</li>
     *   <li>{@code S3} : stockage objet compatible S3 (MinIO gratuit et auto-hébergé, AWS, Scaleway...).</li>
     * </ul>
     * Les deux derniers modes activent le fonctionnement multi-répliques (file d'attente en base) et exigent
     * PostgreSQL.
     */
    public record ArtifactStorage(Mode mode, Optional<Path> sharedDir, Optional<String> s3Endpoint, String s3Region,
                                  Optional<String> s3Bucket, Optional<String> s3AccessKey,
                                  Optional<String> s3SecretKey, String workerId) {

        public enum Mode { LOCAL, SHARED_DIR, S3 }

        public boolean distributed() {
            return mode != Mode.LOCAL;
        }

        @Override
        public String toString() {
            return mode + (mode == Mode.SHARED_DIR ? "(" + sharedDir.orElse(null) + ")" : "")
                    + (mode == Mode.S3 ? "(" + s3Endpoint.orElse(null) + "/" + s3Bucket.orElse(null) + ")" : "")
                    + ", worker=" + workerId;
        }
    }

    /** Toutes interfaces (conteneur) ; l'application de bureau impose 127.0.0.1. */
    static final String DEFAULT_BIND_ADDRESS = "0.0.0.0";
    /** Région par défaut acceptée par MinIO et la plupart des fournisseurs compatibles S3. */
    static final String DEFAULT_S3_REGION = "us-east-1";

    static final int DEFAULT_PORT = 8080;
    static final int DEFAULT_CDXGEN_TIMEOUT_SECONDS = 900;
    static final int MIN_CDXGEN_TIMEOUT_SECONDS = 30;
    static final int MAX_CDXGEN_TIMEOUT_SECONDS = 7_200;
    static final int DEFAULT_MAX_CONCURRENT = 2;
    static final int DEFAULT_MAX_QUEUED = 20;
    static final int DEFAULT_GIT_DEPTH = 1;
    static final int DEFAULT_GIT_TIMEOUT_SECONDS = 600;
    static final int DEFAULT_OSV_TIMEOUT_SECONDS = 30;
    static final int DEFAULT_NVD_MAX_LOOKUPS = 20;
    static final int DEFAULT_NPM_TIMEOUT_SECONDS = 300;
    static final String DEFAULT_NPM_REGISTRY = "https://registry.npmjs.org/";
    static final int MAX_NVD_LOOKUPS = 2_000;
    static final int DEFAULT_KEV_REFRESH_HOURS = 24;
    static final int MAX_KEV_REFRESH_HOURS = 720;
    static final String DEFAULT_KEV_URL =
            "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
    static final String DEFAULT_EPSS_URL = "https://api.first.org/data/v1/epss";
    static final String DEFAULT_NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0";
    static final long DEFAULT_MAX_FILE_BYTES = 2L * 1024 * 1024;
    static final int MAX_PORT = 65_535;
    static final int MAX_WORKERS = 32;
    static final int MAX_QUEUE = 1_000;
    static final int MAX_GIT_DEPTH = 10_000;
    static final long MAX_FILE_BYTES_LIMIT = 50L * 1024 * 1024;

    /** Langages pour lesquels cdxgen/atom sait tagger la cryptographie (voir docs/architecture.md). */
    static final String DEFAULT_CRYPTO_LANGUAGES = "java,python";

    public static AppConfig fromEnvironment() {
        return from(System.getenv());
    }

    public static AppConfig from(Map<String, String> env) {
        Reader r = new Reader(env);
        return new AppConfig(
                r.intValue("PORT", DEFAULT_PORT, 1, MAX_PORT),
                r.string("BIND_ADDRESS", DEFAULT_BIND_ADDRESS),
                Path.of(r.string("DATA_DIR", "./data")).toAbsolutePath().normalize(),
                Optional.ofNullable(r.string("MASTER_KEY", null)),
                Optional.ofNullable(r.string("DATABASE_URL", null)),
                r.string("DATABASE_USER", "chiffrium"),
                Optional.ofNullable(r.string("DATABASE_PASSWORD", null)),
                Optional.ofNullable(r.string("AUDIT_EXPORT_DIR", null)).map(s -> Path.of(s).toAbsolutePath().normalize()),
                r.string("CDXGEN_COMMAND", defaultCdxgenCommand()),
                Duration.ofSeconds(r.intValue("CDXGEN_TIMEOUT_SECONDS", DEFAULT_CDXGEN_TIMEOUT_SECONDS,
                        MIN_CDXGEN_TIMEOUT_SECONDS, MAX_CDXGEN_TIMEOUT_SECONDS)),
                Duration.ofSeconds(MIN_CDXGEN_TIMEOUT_SECONDS),
                Duration.ofSeconds(r.intValue("CDXGEN_MAX_TIMEOUT_SECONDS", MAX_CDXGEN_TIMEOUT_SECONDS,
                        MIN_CDXGEN_TIMEOUT_SECONDS, MAX_CDXGEN_TIMEOUT_SECONDS)),
                r.languages("CDXGEN_CRYPTO_LANGUAGES", DEFAULT_CRYPTO_LANGUAGES),
                r.intValue("MAX_CONCURRENT_ANALYSES", DEFAULT_MAX_CONCURRENT, 1, MAX_WORKERS),
                r.intValue("MAX_QUEUED_ANALYSES", DEFAULT_MAX_QUEUED, 1, MAX_QUEUE),
                r.list("ALLOWED_LOCAL_ROOTS", "", s -> Path.of(s).toAbsolutePath().normalize()),
                r.list("ALLOWED_GIT_HOSTS", "", Function.identity()),
                r.intValue("GIT_CLONE_DEPTH", DEFAULT_GIT_DEPTH, 0, MAX_GIT_DEPTH),
                Duration.ofSeconds(r.intValue("GIT_TIMEOUT_SECONDS", DEFAULT_GIT_TIMEOUT_SECONDS, 1,
                        MAX_CDXGEN_TIMEOUT_SECONDS)),
                r.string("GIT_USERNAME", "oauth2"),
                Optional.ofNullable(r.string("GIT_TOKEN", null)),
                r.bool("CDXGEN_INSTALL_DEPS", false),
                r.string("NPM_COMMAND", windows() ? "npm.cmd" : "npm"),
                r.string("NPM_REGISTRY", DEFAULT_NPM_REGISTRY),
                Duration.ofSeconds(r.intValue("NPM_TIMEOUT_SECONDS", DEFAULT_NPM_TIMEOUT_SECONDS, 1,
                        MAX_CDXGEN_TIMEOUT_SECONDS)),
                r.bool("KEEP_WORKSPACE", false),
                r.bool("OSV_ENABLED", true),
                r.string("OSV_URL", "https://api.osv.dev"),
                Duration.ofSeconds(r.intValue("OSV_TIMEOUT_SECONDS", DEFAULT_OSV_TIMEOUT_SECONDS, 1,
                        MAX_CDXGEN_TIMEOUT_SECONDS)),
                r.string("KEV_URL", DEFAULT_KEV_URL),
                r.string("EPSS_URL", DEFAULT_EPSS_URL),
                r.string("NVD_URL", DEFAULT_NVD_URL),
                r.intValue("NVD_MAX_LOOKUPS", DEFAULT_NVD_MAX_LOOKUPS, 0, MAX_NVD_LOOKUPS),
                Duration.ofHours(r.intValue("KEV_REFRESH_HOURS", DEFAULT_KEV_REFRESH_HOURS, 1, MAX_KEV_REFRESH_HOURS)),
                r.longValue("MAX_SCANNED_FILE_BYTES", DEFAULT_MAX_FILE_BYTES, 1, MAX_FILE_BYTES_LIMIT),
                Optional.ofNullable(r.string("STATIC_DIR", null)).filter(s -> !s.isBlank()).map(Path::of),
                r.list("CORS_ORIGINS", "", Function.identity()),
                r.bool("TRUST_PROXY", false),
                r.bool("EXIT_ON_STDIN_CLOSE", false),
                artifactStorage(r),
                Optional.ofNullable(r.string("DESKTOP_CONTROL_TOKEN", null)));
    }

    private static ArtifactStorage artifactStorage(Reader r) {
        String raw = r.string("ARTIFACT_STORE", "local").toUpperCase(Locale.ROOT).replace('-', '_');
        ArtifactStorage.Mode mode;
        try {
            mode = ArtifactStorage.Mode.valueOf(raw);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("ARTIFACT_STORE=" + raw + " : valeurs possibles local, shared-dir, s3", e);
        }
        ArtifactStorage storage = new ArtifactStorage(mode,
                Optional.ofNullable(r.string("SHARED_ARTIFACTS_DIR", null)).map(s -> Path.of(s).toAbsolutePath().normalize()),
                Optional.ofNullable(r.string("S3_ENDPOINT", null)),
                r.string("S3_REGION", DEFAULT_S3_REGION),
                Optional.ofNullable(r.string("S3_BUCKET", null)),
                Optional.ofNullable(r.string("S3_ACCESS_KEY", null)),
                Optional.ofNullable(r.string("S3_SECRET_KEY", null)),
                r.string("WORKER_ID", defaultWorkerId()));
        if (mode != ArtifactStorage.Mode.LOCAL && r.string("DATABASE_URL", null) == null) {
            throw new IllegalArgumentException("ARTIFACT_STORE=" + raw.toLowerCase(Locale.ROOT)
                    + " (plusieurs répliques) exige une base PostgreSQL partagée (DATABASE_URL)");
        }
        if (mode == ArtifactStorage.Mode.SHARED_DIR && storage.sharedDir().isEmpty()) {
            throw new IllegalArgumentException("ARTIFACT_STORE=shared-dir exige SHARED_ARTIFACTS_DIR");
        }
        if (mode == ArtifactStorage.Mode.S3 && (storage.s3Endpoint().isEmpty() || storage.s3Bucket().isEmpty()
                || storage.s3AccessKey().isEmpty() || storage.s3SecretKey().isEmpty())) {
            throw new IllegalArgumentException(
                    "ARTIFACT_STORE=s3 exige S3_ENDPOINT, S3_BUCKET, S3_ACCESS_KEY et S3_SECRET_KEY");
        }
        return storage;
    }

    /** Nom d'hôte (nom du pod sous Kubernetes) : identifie la réplique qui traite une analyse. */
    private static String defaultWorkerId() {
        String host = System.getenv("HOSTNAME");
        if (host == null || host.isBlank()) {
            host = System.getenv("COMPUTERNAME");
        }
        return host == null || host.isBlank() ? "worker-" + ProcessHandle.current().pid() : host;
    }

    /** Représentation sans secret, pour les logs de démarrage. */
    @Override
    public String toString() {
        return "AppConfig[bind=" + bindAddress + ":" + port + ", dataDir=" + dataDir
                + ", masterKey=" + (masterKey.isPresent() ? "environnement" : "fichier")
                + ", database=" + (databaseUrl.isPresent() ? "postgresql" : "h2")
                + ", auditExportDir=" + auditExportDir.orElse(null) + ", cdxgenCommand=" + cdxgenCommand
                + ", cdxgenTimeout=" + cdxgenDefaultTimeout + ", cryptoLanguages=" + cdxgenCryptoLanguages
                + ", installDeps=" + cdxgenInstallDeps + ", workers=" + maxConcurrentAnalyses
                + ", queue=" + maxQueuedAnalyses + ", localRoots=" + allowedLocalRoots
                + ", gitHosts=" + allowedGitHosts + ", gitDepth=" + gitCloneDepth
                + ", gitToken=" + (gitToken.isPresent() ? "***" : "absent") + ", osv=" + osvEnabled
                + ", staticDir=" + staticDir.orElse(null) + ", trustProxy=" + trustProxy
                + ", artifacts=" + artifactStorage + "]";
    }

    public Path analysesDir() {
        return dataDir.resolve("analyses");
    }

    public Path workspaceDir() {
        return dataDir.resolve("workspace");
    }

    /** Clé maîtresse et jeton d'initialisation (droits restreints au propriétaire). */
    public Path secretsDir() {
        return dataDir.resolve("secrets");
    }

    /** Base H2 chiffrée (sans extension : H2 ajoute .mv.db). */
    public Path databaseFile() {
        return dataDir.resolve("db").resolve("chiffrium");
    }

    /** Caches des sources de renseignement (catalogue KEV...). */
    public Path cacheDir() {
        return dataDir.resolve("cache");
    }

    public Path catalogFile() {
        return dataDir.resolve("catalog").resolve("algorithms.json");
    }

    private static String defaultCdxgenCommand() {
        return windows() ? "cdxgen.cmd" : "cdxgen";
    }

    private static boolean windows() {
        return System.getProperty("os.name", "").toLowerCase(Locale.ROOT).contains("win");
    }

    /**
     * Lecture typée et bornée des variables ; une valeur invalide arrête le démarrage avec un message clair.
     */
    private record Reader(Map<String, String> env) {

        String string(String key, String fallback) {
            String value = env.get(key);
            return value == null || value.isBlank() ? fallback : value.trim();
        }

        int intValue(String key, int fallback, int min, int max) {
            return (int) longValue(key, fallback, min, max);
        }

        long longValue(String key, long fallback, long min, long max) {
            String raw = string(key, null);
            if (raw == null) {
                return fallback;
            }
            try {
                long value = Long.parseLong(raw);
                if (value < min || value > max) {
                    throw new IllegalArgumentException(key + "=" + raw + " hors bornes [" + min + ", " + max + "]");
                }
                return value;
            } catch (NumberFormatException e) {
                throw new IllegalArgumentException(key + "=" + raw + " n'est pas un nombre", e);
            }
        }

        boolean bool(String key, boolean fallback) {
            String raw = string(key, null);
            return raw == null ? fallback : Boolean.parseBoolean(raw);
        }

        <T> List<T> list(String key, String fallback, Function<String, T> mapper) {
            return Arrays.stream(string(key, fallback).split(","))
                    .map(String::trim)
                    .filter(s -> !s.isEmpty())
                    .map(mapper)
                    .toList();
        }

        Set<Language> languages(String key, String fallback) {
            Set<Language> result = EnumSet.noneOf(Language.class);
            for (String id : list(key, fallback, Function.identity())) {
                result.add(Language.fromId(id)
                        .orElseThrow(() -> new IllegalArgumentException(key + " : langage inconnu '" + id + "'")));
            }
            return result;
        }
    }
}
