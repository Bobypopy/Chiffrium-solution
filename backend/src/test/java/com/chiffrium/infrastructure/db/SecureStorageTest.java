package com.chiffrium.infrastructure.db;

import com.chiffrium.SecurityFixture;
import com.chiffrium.application.security.Actor;
import com.chiffrium.application.settings.Settings;
import com.chiffrium.application.settings.SettingsService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Base locale : chiffrement du fichier, secrets masqués et chiffrés, détection de toute altération du
 * journal d'audit.
 */
class SecureStorageTest {

    private static final String NVD_KEY = "cle-nvd-tres-secrete-1234";
    private static final String IP = "127.0.0.1";

    @Test
    void auditTamperingIsDetected(@TempDir Path dir) throws Exception {
        try (SecurityFixture fx = new SecurityFixture(dir)) {
            fx.setupAdmin();
            fx.audit.record(Actor.SYSTEM, "TEST", "cible", "détail d'origine");
            fx.audit.record(Actor.SYSTEM, "TEST", "cible", "suivant");
            assertThat(fx.audit.verify().intact()).isTrue();

            long tampered = fx.audit.search(null, "TEST", 10, 0).stream()
                    .filter(e -> "détail d'origine".equals(e.details()))
                    .findFirst().orElseThrow().sequence();
            try (Connection c = fx.database.connection();
                 PreparedStatement st = c.prepareStatement("UPDATE audit_log SET details = ? WHERE sequence = ?")) {
                st.setString(1, "détail falsifié");
                st.setLong(2, tampered);
                assertThat(st.executeUpdate()).isEqualTo(1);
            }
            assertThat(fx.audit.verify().intact()).isFalse();
            assertThat(fx.audit.verify().firstBrokenSeq()).isEqualTo(tampered);
        }
    }

    @Test
    void secretsAreMaskedKeptAndEncryptedAtRest(@TempDir Path dir) throws Exception {
        try (SecurityFixture fx = new SecurityFixture(dir)) {
            Actor admin = fx.auth.authenticate(fx.setupAdmin(), IP).actor();
            Settings defaults = Settings.defaults();
            Settings withKey = new Settings(null, null,
                    new Settings.Intelligence(true, true, true, true, NVD_KEY), null, null);

            Settings view = fx.settings.update(admin, withKey);
            assertThat(view.intelligence().nvdApiKey()).isEqualTo(SettingsService.MASK);
            assertThat(view.storage()).isEqualTo(defaults.storage());

            // Renvoyer le masque (formulaire inchangé) conserve le secret.
            fx.settings.update(admin, new Settings(null, null,
                    new Settings.Intelligence(false, true, true, true, SettingsService.MASK), null, null));
            assertThat(fx.settings.current().intelligence().nvdApiKey()).isEqualTo(NVD_KEY);
            assertThat(fx.audit.search(null, "SETTINGS_UPDATED", 10, 0))
                    .allSatisfy(e -> assertThat(e.details()).doesNotContain(NVD_KEY));
        }
        assertThat(filesContaining(dir, NVD_KEY)).isZero();
        assertThat(filesContaining(dir, SecurityFixture.ADMIN)).as("fichier H2 chiffré").isZero();
    }

    @Test
    void settingsSurviveARestart(@TempDir Path dir) {
        try (SecurityFixture fx = new SecurityFixture(dir)) {
            Actor admin = fx.auth.authenticate(fx.setupAdmin(), IP).actor();
            fx.settings.update(admin, new Settings(new Settings.Storage(30, 500, true), null, null, null, null));
        }
        try (SecurityFixture reopened = new SecurityFixture(dir)) {
            assertThat(reopened.settings.current().storage()).isEqualTo(new Settings.Storage(30, 500, true));
            assertThat(reopened.auth.setupRequired()).isFalse();
            assertThat(reopened.audit.verify().intact()).isTrue();
        }
    }

    private static long filesContaining(Path dir, String needle) throws Exception {
        byte[] pattern = needle.getBytes(StandardCharsets.UTF_8);
        try (Stream<Path> files = Files.walk(dir)) {
            return files.filter(Files::isRegularFile).filter(f -> contains(read(f), pattern)).count();
        }
    }

    private static byte[] read(Path file) {
        try {
            return Files.readAllBytes(file);
        } catch (Exception e) {
            return new byte[0];
        }
    }

    private static boolean contains(byte[] data, byte[] pattern) {
        outer:
        for (int i = 0; i <= data.length - pattern.length; i++) {
            for (int j = 0; j < pattern.length; j++) {
                if (data[i + j] != pattern[j]) {
                    continue outer;
                }
            }
            return true;
        }
        return false;
    }
}
