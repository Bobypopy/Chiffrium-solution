package com.chiffrium;

import com.chiffrium.application.security.AuditService;
import com.chiffrium.application.security.AuthService;
import com.chiffrium.application.security.GroupService;
import com.chiffrium.application.security.NotificationService;
import com.chiffrium.application.security.SetupTokenStore;
import com.chiffrium.application.security.UserService;
import com.chiffrium.application.settings.SettingsService;
import com.chiffrium.infrastructure.crypto.Pbkdf2PasswordHasher;
import com.chiffrium.infrastructure.db.Database;
import com.chiffrium.infrastructure.db.JdbcAuditRepository;
import com.chiffrium.infrastructure.db.JdbcFavoriteRepository;
import com.chiffrium.infrastructure.db.JdbcGroupRepository;
import com.chiffrium.infrastructure.db.JdbcNotificationRepository;
import com.chiffrium.infrastructure.db.JdbcSessionRepository;
import com.chiffrium.infrastructure.db.JdbcSettingsRepository;
import com.chiffrium.infrastructure.db.JdbcUserRepository;

import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.Optional;

/**
 * Services de sécurité réels sur une base H2 chiffrée temporaire, avec une horloge pilotable.
 */
public final class SecurityFixture implements AutoCloseable {

    /** Itérations réduites : les tests vérifient la logique, pas le coût du hachage. */
    private static final int TEST_ITERATIONS = 1_000;
    public static final String SETUP_TOKEN = "jeton-installation-test";
    public static final String ADMIN = "admin";
    public static final char[] ADMIN_PASSWORD = "phrase de passe solide".toCharArray();

    public final MutableClock clock = new MutableClock(Instant.parse("2026-03-01T08:00:00Z"));
    public final Database database;
    public final AuditService audit;
    public final SettingsService settings;
    public final AuthService auth;
    public final UserService users;
    public final JdbcUserRepository userRepository;
    public final JdbcAuditRepository auditRepository;
    public final JdbcGroupRepository groupRepository;
    public final JdbcFavoriteRepository favoriteRepository;
    public final GroupService groups;
    public final NotificationService notifications;
    public final TokenStore setupTokens = new TokenStore();
    /** Relais de courriel utilisé par les notifications ; null = aucun relais configuré. */
    public volatile com.chiffrium.application.port.MailSender mailSender;

    public SecurityFixture(Path dir) {
        database = Database.h2(dir.resolve("db/test"), "cle-fichier-test", "cle-utilisateur-test");
        auditRepository = new JdbcAuditRepository(database);
        audit = new AuditService(auditRepository, clock);
        settings = new SettingsService(new JdbcSettingsRepository(database, TestSupport.cipher(), TestSupport.MAPPER),
                audit);
        Pbkdf2PasswordHasher hasher = new Pbkdf2PasswordHasher(TEST_ITERATIONS);
        userRepository = new JdbcUserRepository(database);
        JdbcSessionRepository sessions = new JdbcSessionRepository(database);
        auth = new AuthService(userRepository, sessions, hasher, audit, settings, setupTokens, clock);
        // Relais de courriel injectable : les tests qui s'y intéressent posent un expéditeur en mémoire.
        notifications = new NotificationService(new JdbcNotificationRepository(database), userRepository,
                Optional::empty, () -> Optional.ofNullable(mailSender), clock);
        users = new UserService(userRepository, sessions, hasher, audit, notifications, clock);
        groupRepository = new JdbcGroupRepository(database);
        favoriteRepository = new JdbcFavoriteRepository(database, clock);
        groups = new GroupService(groupRepository, userRepository, audit, notifications,
                () -> settings.current().collaboration(), clock);
    }

    /** Installe le premier administrateur et retourne son jeton de session. */
    public String setupAdmin() {
        return auth.setup(SETUP_TOKEN, ADMIN, ADMIN_PASSWORD.clone(), "Administrateur", "127.0.0.1").token();
    }

    @Override
    public void close() {
        database.close();
    }

    /** Jeton d'installation en mémoire. */
    public static final class TokenStore implements SetupTokenStore {
        private boolean consumed;

        @Override
        public Optional<String> current() {
            return consumed ? Optional.empty() : Optional.of(SETUP_TOKEN);
        }

        @Override
        public void consume() {
            consumed = true;
        }
    }

    /** Horloge avançable manuellement. */
    public static final class MutableClock extends Clock {
        private Instant now;

        MutableClock(Instant start) {
            this.now = start;
        }

        public void advance(Duration duration) {
            now = now.plus(duration);
        }

        @Override
        public ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return now;
        }
    }
}
