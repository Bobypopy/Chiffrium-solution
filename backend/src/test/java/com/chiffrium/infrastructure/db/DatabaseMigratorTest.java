package com.chiffrium.infrastructure.db;

import com.chiffrium.SecurityFixture;
import com.chiffrium.application.security.Actor;
import com.chiffrium.domain.security.Group;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.Map;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Recopie d'une base vers une autre. Le test se fait entre deux bases H2 : ce qui est vérifié ici, c'est la
 * mécanique de copie (contenu identique, ordre des clés étrangères, refus d'une cible déjà peuplée), pas le
 * dialecte de destination.
 */
class DatabaseMigratorTest {

    @Test
    void copiesEveryTableIntoAnEmptyDatabase(@TempDir Path dir) throws Exception {
        try (SecurityFixture source = new SecurityFixture(dir.resolve("source"))) {
            source.setupAdmin();
            source.audit.record(Actor.SYSTEM, "TEST", "cible", "une entrée de journal");
            source.groups.create(Actor.SYSTEM, "Équipe paiement", "cartes", Group.Visibility.PRIVATE);

            try (Database target = Database.h2(dir.resolve("cible/db"), "cle-fichier", "cle-utilisateur")) {
                DatabaseMigrator.Result result = DatabaseMigrator.copy(source.database, target, false);

                Map<String, Integer> copied = result.tables().stream()
                        .collect(Collectors.toMap(DatabaseMigrator.TableResult::table,
                                DatabaseMigrator.TableResult::rows));
                assertThat(copied).containsEntry("users", 1).containsEntry("user_groups", 1);
                assertThat(copied.get("audit_log")).isGreaterThan(0);
                assertThat(result.total()).isEqualTo(copied.values().stream().mapToInt(Integer::intValue).sum());
                // Le contenu, pas seulement le compte : la chaîne du journal d'audit doit rester vérifiable.
                assertThat(rows(target, "audit_log")).isEqualTo(rows(source.database, "audit_log"));
                assertThat(hashes(target)).isEqualTo(hashes(source.database));
            }
        }
    }

    @Test
    void refusesToMixTwoInstallations(@TempDir Path dir) throws Exception {
        try (SecurityFixture source = new SecurityFixture(dir.resolve("source"));
             SecurityFixture occupied = new SecurityFixture(dir.resolve("cible"))) {
            source.setupAdmin();
            occupied.setupAdmin();

            assertThatThrownBy(() -> DatabaseMigrator.copy(source.database, occupied.database, false))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("users");
            // La cible n'a pas bougé : toujours son seul administrateur.
            assertThat(rows(occupied.database, "users")).isEqualTo(1);
        }
    }

    private static int rows(Database database, String table) throws Exception {
        try (Connection connection = database.connection();
             Statement statement = connection.createStatement();
             ResultSet rs = statement.executeQuery("SELECT COUNT(*) FROM " + table)) {
            return rs.next() ? rs.getInt(1) : -1;
        }
    }

    private static String hashes(Database database) throws Exception {
        try (Connection connection = database.connection();
             Statement statement = connection.createStatement();
             ResultSet rs = statement.executeQuery("SELECT hash FROM audit_log ORDER BY sequence")) {
            StringBuilder all = new StringBuilder();
            while (rs.next()) {
                all.append(rs.getString(1)).append('\n');
            }
            return all.toString();
        }
    }
}
