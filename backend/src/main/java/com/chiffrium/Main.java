package com.chiffrium;

import com.chiffrium.api.ApiServer;
import com.chiffrium.application.AnalysisPipeline;
import com.chiffrium.application.AnalysisAccess;
import com.chiffrium.application.AnalysisService;
import com.chiffrium.application.CatalogRequestService;
import com.chiffrium.application.CatalogService;
import com.chiffrium.application.InMemoryJobQueue;
import com.chiffrium.application.DetectorProvider;
import com.chiffrium.application.PipelineSettings;
import com.chiffrium.application.RetentionService;
import com.chiffrium.application.port.AlertSink;
import com.chiffrium.application.port.AnalysisRepository;
import com.chiffrium.application.port.ArtifactStore;
import com.chiffrium.application.port.AuditSink;
import com.chiffrium.application.port.CatalogRepository;
import com.chiffrium.application.port.JobQueue;
import com.chiffrium.application.port.MailSender;
import com.chiffrium.application.port.PasswordHasher;
import com.chiffrium.application.port.SecretCipher;
import com.chiffrium.application.port.SbomGenerator;
import com.chiffrium.application.port.VulnerabilityScanner;
import com.chiffrium.application.security.AccountService;
import com.chiffrium.application.security.AuditArchiveService;
import com.chiffrium.application.security.AuditService;
import com.chiffrium.application.security.GroupService;
import com.chiffrium.application.security.AuthService;
import com.chiffrium.application.security.NotificationService;
import com.chiffrium.application.security.SsoService;
import com.chiffrium.application.security.UserService;
import com.chiffrium.application.settings.Settings;
import com.chiffrium.application.settings.SettingsService;
import com.chiffrium.infrastructure.alerts.WebhookAlertSink;
import com.chiffrium.infrastructure.audit.DirectoryAuditSink;
import com.chiffrium.infrastructure.audit.WebhookAuditSink;
import com.chiffrium.domain.model.Language;
import com.chiffrium.infrastructure.cdxgen.CdxgenCryptoDetector;
import com.chiffrium.infrastructure.cdxgen.CdxgenSbomGenerator;
import com.chiffrium.infrastructure.cdxgen.CycloneDxCbomWriter;
import com.chiffrium.infrastructure.cdxgen.CycloneDxLibraryReader;
import com.chiffrium.infrastructure.cdxgen.SliceCallEdgeExtractor;
import com.chiffrium.infrastructure.config.AppConfig;
import com.chiffrium.infrastructure.crypto.AesGcmSecretCipher;
import com.chiffrium.infrastructure.crypto.FileSetupTokenStore;
import com.chiffrium.infrastructure.crypto.MasterKey;
import com.chiffrium.infrastructure.crypto.Pbkdf2PasswordHasher;
import com.chiffrium.infrastructure.db.Database;
import com.chiffrium.infrastructure.db.JdbcAnalysisRepository;
import com.chiffrium.infrastructure.db.JdbcAuditRepository;
import com.chiffrium.infrastructure.db.JdbcCatalogRequestRepository;
import com.chiffrium.infrastructure.db.JdbcFavoriteRepository;
import com.chiffrium.infrastructure.db.JdbcGroupRepository;
import com.chiffrium.infrastructure.db.JdbcJobQueue;
import com.chiffrium.infrastructure.db.JdbcNotificationRepository;
import com.chiffrium.infrastructure.db.JdbcSessionRepository;
import com.chiffrium.infrastructure.db.JdbcSettingsRepository;
import com.chiffrium.infrastructure.db.JdbcUserRepository;
import com.chiffrium.infrastructure.findings.FindingRuleLoader;
import com.chiffrium.infrastructure.findings.SecurityFindingDetector;
import com.chiffrium.infrastructure.git.GitSourceFetcher;
import com.chiffrium.infrastructure.intelligence.EnrichingVulnerabilityScanner;
import com.chiffrium.infrastructure.json.JsonMapper;
import com.chiffrium.infrastructure.licenses.LicensePolicyLoader;
import com.chiffrium.infrastructure.logging.LoggingSetup;
import com.chiffrium.infrastructure.mail.SmtpMailSender;
import com.chiffrium.infrastructure.material.MaterialDetector;
import com.chiffrium.infrastructure.npm.NpmLockfileGenerator;
import com.chiffrium.infrastructure.oidc.OidcIdentityProvider;
import com.chiffrium.infrastructure.osv.OsvVulnerabilityScanner;
import com.chiffrium.infrastructure.persistence.FileCatalogRepository;
import com.chiffrium.infrastructure.persistence.FileSystemAnalysisRepository;
import com.chiffrium.infrastructure.process.ProcessRunner;
import com.chiffrium.infrastructure.rules.RuleBasedCryptoDetector;
import com.chiffrium.infrastructure.rules.RulePack;
import com.chiffrium.infrastructure.rules.RulePackLoader;
import com.chiffrium.infrastructure.sarif.SarifReportExporter;
import com.chiffrium.infrastructure.scan.FileSystemProjectScanner;
import com.chiffrium.infrastructure.storage.FileArtifactStore;
import com.chiffrium.infrastructure.storage.S3ArtifactStore;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.time.Clock;
import java.time.Duration;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * Racine de composition : assemble les adaptateurs et démarre soit l'API HTTP (par défaut),
 * soit une analyse unique en ligne de commande (intégration CI/CD).
 */
public final class Main {

    private static final Logger LOG = LoggerFactory.getLogger(Main.class);
    private static final int END_OF_STREAM = -1;
    /** Périodicité de la purge (rétention, quota, sessions expirées). */
    private static final Duration MAINTENANCE_PERIOD = Duration.ofHours(1);
    private static final Duration MAINTENANCE_INITIAL_DELAY = Duration.ofMinutes(1);
    /** Usages des sous-clés dérivées de la clé maîtresse (les changer rend les données existantes illisibles). */
    private static final String KEY_ARTIFACTS = "artifacts";
    private static final String PRODUCT_NAME = "Chiffrium";
    private static final String LICENSE_SUMMARY = "Logiciel propriétaire, usage interne uniquement (voir LICENSE).";
    private static final String THIRD_PARTY_RESOURCE = "/legal/third-party.json";
    private static final String KEY_SETTINGS = "settings";
    private static final String KEY_DB_FILE = "h2-file";
    private static final String KEY_DB_USER = "h2-user";

    private Main() {
    }

    public static void main(String[] args) {
        AppConfig config = AppConfig.fromEnvironment();
        Application application = new Application(config);
        if (args.length > 0 && CommandLine.handles(args[0])) {
            System.exit(new CommandLine(application).run(args));
        }
        application.startServer();
        if (config.exitOnStdinClose()) {
            exitWhenParentCloses();
        }
    }

    /**
     * Application de bureau : le processus parent garde l'entrée standard ouverte. Sa fermeture (arrêt normal
     * ou plantage du parent) déclenche un arrêt propre (hooks : fin des analyses, fermeture de la base),
     * y compris sous Windows où le parent ne peut pas envoyer de signal d'arrêt.
     */
    private static void exitWhenParentCloses() {
        Thread watcher = new Thread(() -> {
            try {
                while (System.in.read() != END_OF_STREAM) {
                    // Contenu ignoré : seule la fermeture compte.
                }
            } catch (IOException e) {
                LOG.debug("Entrée standard fermée", e);
            }
            LOG.info("Processus parent terminé : arrêt de l'application");
            System.exit(0);
        }, "parent-watcher");
        watcher.setDaemon(true);
        watcher.start();
    }

    /**
     * Graphe d'objets de l'application, construit une seule fois.
     */
    static final class Application {
        final AppConfig config;
        final ObjectMapper mapper = JsonMapper.create();
        final Clock clock = Clock.systemUTC();
        final String version = Optional.ofNullable(Main.class.getPackage().getImplementationVersion()).orElse("dev");
        final Database database;
        final JdbcAuditRepository auditRepository;
        final AuditService audit;
        final SettingsService settings;
        final AuthService auth;
        final UserService users;
        final SsoService sso;
        final GroupService groups;
        final CatalogRequestService catalogRequests;
        final NotificationService notifications;
        final AccountService account;
        final AuditArchiveService auditArchive;
        final FileSetupTokenStore setupTokens;
        final AnalysisRepository repository;
        final CatalogRepository catalogRepository;
        final CatalogService catalogService;
        final SbomGenerator sbomGenerator;
        final List<RulePack> rulePacks;
        final AnalysisPipeline pipeline;
        final AnalysisService analysisService;
        final RetentionService retention;

        Application(AppConfig config) {
            this.config = config;
            LoggingSetup.useDataDir(config.dataDir());
            LOG.info("Démarrage de Chiffrium {} avec {}", version, config);
            MasterKey masterKey = MasterKey.load(config.masterKey(), config.secretsDir());
            this.database = config.databaseUrl()
                    .map(url -> Database.postgresql(url, config.databaseUser(), config.databasePassword().orElse(null)))
                    .orElseGet(() -> Database.h2(config.databaseFile(), masterKey.deriveHex(KEY_DB_FILE),
                            masterKey.deriveHex(KEY_DB_USER)));
            this.auditRepository = new JdbcAuditRepository(database);
            this.audit = new AuditService(auditRepository, clock);
            this.settings = new SettingsService(new JdbcSettingsRepository(database,
                    new AesGcmSecretCipher(masterKey.derive(KEY_SETTINGS)), mapper), audit);
            PasswordHasher hasher = new Pbkdf2PasswordHasher(Pbkdf2PasswordHasher.DEFAULT_ITERATIONS);
            JdbcUserRepository userRepository = new JdbcUserRepository(database);
            JdbcSessionRepository sessionRepository = new JdbcSessionRepository(database);
            this.setupTokens = new FileSetupTokenStore(config.secretsDir());
            this.auth = new AuthService(userRepository, sessionRepository, hasher, audit, settings, setupTokens, clock);
            this.notifications = new NotificationService(new JdbcNotificationRepository(database), userRepository,
                    this::alertSink, this::mailSender, clock);
            this.users = new UserService(userRepository, sessionRepository, hasher, audit, notifications, clock);
            this.sso = new SsoService(new OidcIdentityProvider(mapper, config.osvTimeout()), userRepository, auth,
                    settings, audit, clock);
            this.repository = analysisRepository(new AesGcmSecretCipher(masterKey.derive(KEY_ARTIFACTS)));
            this.catalogRepository = new FileCatalogRepository(config.catalogFile(), mapper);
            this.catalogService = new CatalogService(catalogRepository, audit);
            JdbcGroupRepository groupRepository = new JdbcGroupRepository(database);
            this.groups = new GroupService(groupRepository, userRepository, audit, notifications,
                    () -> settings.current().collaboration(), clock);
            JdbcCatalogRequestRepository catalogRequestRepository = new JdbcCatalogRequestRepository(database, mapper);
            this.catalogRequests = new CatalogRequestService(catalogRequestRepository, catalogService, groupRepository,
                    audit, notifications, clock);
            this.auditArchive = new AuditArchiveService(auditRepository, audit, this::auditSinks,
                    () -> settings.current().audit().retentionDays(), clock);
            AnalysisAccess access = new AnalysisAccess(groupRepository);
            JdbcFavoriteRepository favorites = new JdbcFavoriteRepository(database, clock);
            this.account = new AccountService(userRepository, groupRepository, favorites, catalogRequestRepository,
                    repository, notifications, audit, clock);
            this.rulePacks = new RulePackLoader(mapper).loadBuiltIn();
            ProcessRunner processRunner = new ProcessRunner();
            this.sbomGenerator = new CdxgenSbomGenerator(config.cdxgenCommand(), config.cdxgenCryptoLanguages(),
                    config.cdxgenInstallDeps(), processRunner);

            SecurityFindingDetector findingDetector = new SecurityFindingDetector(
                    new FindingRuleLoader(mapper).loadBuiltIn());
            DetectorProvider detectors = assetFactory -> List.of(
                    new CdxgenCryptoDetector(assetFactory, mapper),
                    new RuleBasedCryptoDetector(rulePacks, assetFactory),
                    new MaterialDetector(assetFactory),
                    findingDetector);
            VulnerabilityScanner osv = new OsvVulnerabilityScanner(mapper, config.osvUrl(), config.osvTimeout());
            // OSV_ENABLED coupe définitivement l'accès réseau ; le réglage d'administration le coupe à chaud.
            VulnerabilityScanner switchable = libraries ->
                    config.osvEnabled() && settings.current().intelligence().osv() ? osv.scan(libraries) : Map.of();
            VulnerabilityScanner vulnerabilityScanner = new EnrichingVulnerabilityScanner(switchable,
                    () -> settings.current().intelligence(), mapper,
                    new EnrichingVulnerabilityScanner.Sources(config.kevUrl(), config.epssUrl(), config.nvdUrl(),
                            config.nvdMaxLookups(), config.kevRefresh()),
                    config.osvTimeout(), config.cacheDir(), clock);
            PipelineSettings pipelineSettings = new PipelineSettings(config.workspaceDir(), config.keepWorkspace(),
                    config.cdxgenDefaultTimeout(), config.cdxgenMinTimeout(), config.cdxgenMaxTimeout(), version);

            this.pipeline = new AnalysisPipeline(
                    new GitSourceFetcher(config.allowedLocalRoots(), config.allowedGitHosts(), config.gitCloneDepth(),
                            config.gitTimeout(), config.gitUsername(), config.gitToken()),
                    new FileSystemProjectScanner(config.maxScannedFileBytes()),
                    List.of(new NpmLockfileGenerator(processRunner, config.npmCommand(), config.npmRegistry(),
                            config.npmTimeout(), () -> settings.current().analysis().generateNpmLockfile())),
                    sbomGenerator,
                    detectors,
                    new SliceCallEdgeExtractor(mapper),
                    new CycloneDxLibraryReader(mapper, LicensePolicyLoader.loadBuiltIn(mapper)),
                    vulnerabilityScanner,
                    new CycloneDxCbomWriter(mapper, clock, version),
                    List.of(new SarifReportExporter(mapper)),
                    repository,
                    catalogRepository,
                    clock,
                    pipelineSettings);
            JobQueue queue = config.artifactStorage().distributed()
                    ? new JdbcJobQueue(database, config.artifactStorage().workerId(), clock)
                    : new InMemoryJobQueue();
            this.analysisService = new AnalysisService(pipeline, repository, audit, access, favorites, notifications,
                    queue, new AnalysisService.Settings(clock, () -> UUID.randomUUID().toString(),
                    () -> settings.current().storage().keepRawOutputs(), config.maxConcurrentAnalyses(),
                    config.maxQueuedAnalyses()));
            this.retention = new RetentionService(analysisService, repository, () -> settings.current().storage(),
                    config.workspaceDir(), clock);
            LOG.info("cdxgen : version {}", sbomGenerator.version());
        }

        /**
         * Instance seule : artefacts dans le dossier de données. Plusieurs répliques : métadonnées en base
         * (PostgreSQL) et artefacts dans un dossier partagé ou un stockage objet S3.
         */
        private AnalysisRepository analysisRepository(SecretCipher cipher) {
            AppConfig.ArtifactStorage storage = config.artifactStorage();
            ArtifactStore store = switch (storage.mode()) {
                case LOCAL -> null;
                case SHARED_DIR -> new FileArtifactStore(storage.sharedDir().orElseThrow());
                case S3 -> new S3ArtifactStore(new S3ArtifactStore.Config(URI.create(storage.s3Endpoint().orElseThrow()),
                        storage.s3Region(), storage.s3Bucket().orElseThrow(), storage.s3AccessKey().orElseThrow(),
                        storage.s3SecretKey().orElseThrow()), config.osvTimeout(), clock).ensureBucket();
            };
            if (store == null) {
                return new FileSystemAnalysisRepository(config.analysesDir(), mapper, cipher);
            }
            return new JdbcAnalysisRepository(database, mapper, cipher, store, config.workspaceDir().resolve("artifacts"));
        }

        /** Relais SMTP des notifications, relu à chaque envoi (les réglages changent à chaud). */
        Optional<MailSender> mailSender() {
            Settings.Email email = settings.current().email();
            return email != null && email.usable()
                    ? Optional.of(new SmtpMailSender(email, config.osvTimeout())) : Optional.empty();
        }

        /** Canal d'alerte externe gratuit (Slack, Mattermost, Discord, Teams...), relu à chaque envoi. */
        Optional<AlertSink> alertSink() {
            Settings.Alerts alerts = settings.current().alerts();
            if (alerts == null || alerts.webhookUrl() == null) {
                return Optional.empty();
            }
            return Optional.of(new WebhookAlertSink(alerts.webhookUrl(), alerts.format(), mapper, config.osvTimeout()));
        }

        void startServer() {
            if (!config.artifactStorage().distributed()) {
                analysisService.recoverInterrupted();
            }
            if (!config.keepWorkspace()) {
                // Clones laissés par un arrêt brutal précédent.
                retention.cleanWorkspaces();
            }
            if (auth.setupRequired()) {
                setupTokens.announce();
            }
            ScheduledExecutorService maintenance = Executors.newSingleThreadScheduledExecutor(runnable -> {
                Thread thread = new Thread(runnable, "maintenance");
                thread.setDaemon(true);
                return thread;
            });
            maintenance.scheduleAtFixedRate(this::maintain, MAINTENANCE_INITIAL_DELAY.toSeconds(),
                    MAINTENANCE_PERIOD.toSeconds(), TimeUnit.SECONDS);
            ApiServer server = new ApiServer(new ApiServer.Dependencies(analysisService, catalogService, repository,
                    auth, sso, users, audit, auditArchive, settings, retention, groups, catalogRequests,
                    notifications, account,
                    info(), about(),
                    this::externalServices, mapper, clock, config.trustProxy(), config.desktopControlToken()))
                    .start(config.bindAddress(), config.port(), config.staticDir(), config.corsOrigins());
            Runtime.getRuntime().addShutdownHook(new Thread(() -> {
                LOG.info("Arrêt en cours : fin des analyses en cours (délai de grâce)");
                server.stop();
                maintenance.shutdownNow();
                analysisService.close();
                database.close();
            }, "shutdown"));
            LOG.info("API disponible sur {}:{}", config.bindAddress(), server.port());
        }

        /** Destinations d'archivage du journal d'audit : dossier (configuration) et webhook (paramètres). */
        List<AuditSink> auditSinks() {
            List<AuditSink> sinks = new ArrayList<>();
            config.auditExportDir().ifPresent(dir -> sinks.add(new DirectoryAuditSink(dir, mapper, clock)));
            Settings.Audit auditSettings = settings.current().audit();
            if (auditSettings.webhookUrl() != null) {
                sinks.add(new WebhookAuditSink(auditSettings.webhookUrl(), auditSettings.webhookSecret(), mapper,
                        config.osvTimeout()));
            }
            return sinks;
        }

        /** Tâche périodique : sessions expirées, rétention et quota. Ne doit jamais interrompre le planificateur. */
        void maintain() {
            try {
                int sessions = auth.purgeExpiredSessions();
                if (sessions > 0) {
                    LOG.info("{} session(s) expirée(s) supprimée(s)", sessions);
                }
                retention.apply();
                int archived = auditArchive.exportPending();
                if (archived > 0) {
                    LOG.info("{} entrée(s) du journal d'audit archivée(s)", archived);
                }
                auditArchive.applyRetention();
                int abandoned = analysisService.failAbandoned();
                if (abandoned > 0) {
                    LOG.warn("{} analyse(s) abandonnée(s) par une réplique arrêtée", abandoned);
                }
                notifications.purgeOld();
            } catch (RuntimeException e) {
                LOG.error("Échec de la maintenance périodique", e);
            }
        }

        /** Informations légales statiques (licence, composants tiers). */
        Map<String, Object> about() {
            Map<String, Object> about = new LinkedHashMap<>();
            about.put("product", PRODUCT_NAME);
            about.put("version", version);
            about.put("license", LICENSE_SUMMARY);
            about.put("thirdParty", readResource(THIRD_PARTY_RESOURCE));
            return about;
        }

        /** Services réseau contactés avec la configuration courante (transparence, RGPD). */
        List<String> externalServices() {
            Settings current = settings.current();
            List<String> services = new ArrayList<>();
            services.add("Dépôts Git analysés (clonage à la demande)");
            if (config.osvEnabled() && current.intelligence().osv()) {
                services.add("OSV (" + config.osvUrl() + ") : identifiants de paquets et versions");
            }
            if (current.intelligence().kev()) {
                services.add("CISA KEV (" + config.kevUrl() + ") : téléchargement du catalogue");
            }
            if (current.intelligence().epss()) {
                services.add("FIRST EPSS (" + config.epssUrl() + ") : identifiants CVE");
            }
            if (current.intelligence().nvd()) {
                services.add("NVD (" + config.nvdUrl() + ") : identifiants CVE");
            }
            if (current.analysis().generateNpmLockfile()) {
                services.add("Registre npm (" + config.npmRegistry() + ") : résolution des dépendances JavaScript");
            }
            if (current.oidc().enabled()) {
                services.add("Fournisseur d'identité SSO (" + current.oidc().issuer() + ")");
            }
            if (current.audit().webhookUrl() != null) {
                services.add("Collecteur du journal d'audit (" + current.audit().webhookUrl() + ")");
            }
            if (current.alerts() != null && current.alerts().webhookUrl() != null) {
                services.add("Canal d'alertes (" + current.alerts().format() + ") : titres des notifications");
            }
            if (config.artifactStorage().mode() == AppConfig.ArtifactStorage.Mode.S3) {
                services.add("Stockage objet S3 (" + config.artifactStorage().s3Endpoint().orElse("") + ")");
            }
            return services;
        }

        private Object readResource(String resource) {
            try (InputStream in = Main.class.getResourceAsStream(resource)) {
                return in == null ? Map.of() : mapper.readValue(in, Map.class);
            } catch (IOException e) {
                LOG.warn("Ressource illisible : {}", resource, e);
                return Map.of();
            }
        }

        Map<String, Object> info() {
            Set<Language> ruleLanguages = EnumSet.noneOf(Language.class);
            rulePacks.forEach(pack -> ruleLanguages.addAll(pack.languages()));
            Map<String, Object> info = new LinkedHashMap<>();
            info.put("version", version);
            info.put("cdxgenVersion", sbomGenerator.version());
            info.put("ruleLanguages", ruleLanguages);
            info.put("cdxgenCryptoLanguages", config.cdxgenCryptoLanguages());
            info.put("localAnalysisEnabled", !config.allowedLocalRoots().isEmpty());
            info.put("vulnerabilityScanEnabled", config.osvEnabled() && settings.current().intelligence().osv());
            info.put("cdxgenDefaultTimeoutSeconds", config.cdxgenDefaultTimeout().toSeconds());
            info.put("cdxgenMaxTimeoutSeconds", config.cdxgenMaxTimeout().toSeconds());
            info.put("maxConcurrentAnalyses", config.maxConcurrentAnalyses());
            return info;
        }
    }
}
