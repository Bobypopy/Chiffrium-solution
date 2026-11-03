package com.chiffrium;

import com.chiffrium.domain.security.AuditEvent;
import com.chiffrium.domain.security.Role;
import com.chiffrium.infrastructure.config.AppConfig;
import com.fasterxml.jackson.databind.JsonNode;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** reset-password : rendre l'accès au seul administrateur local qui a perdu son mot de passe. */
class PasswordRecoveryCommandTest {

    private static final String LOOPBACK = "127.0.0.1";
    private static final String FORGOTTEN = "phrase oubliée du test";

    @TempDir
    Path dataDir;

    private Main.Application open() {
        return new Main.Application(AppConfig.from(Map.of("DATA_DIR", dataDir.toString(), "OSV_ENABLED", "false",
                "CDXGEN_COMMAND", "cdxgen-absent-pour-les-tests")));
    }

    /** Premier administrateur installé, avec une session ouverte ; renvoie le jeton de session. */
    private String installAdmin() {
        Main.Application application = open();
        try {
            String setupToken = application.setupTokens.current().orElseThrow();
            return application.auth.setup(setupToken, "admin", FORGOTTEN.toCharArray(), "Administrateur", LOOPBACK)
                    .token();
        } finally {
            application.database.close();
        }
    }

    private record Run(int code, String output) {
    }

    private Run run(String... args) {
        PrintStream original = System.out;
        ByteArrayOutputStream captured = new ByteArrayOutputStream();
        System.setOut(new PrintStream(captured, true, StandardCharsets.UTF_8));
        try {
            return new Run(new CommandLine(open()).run(args), captured.toString(StandardCharsets.UTF_8));
        } finally {
            System.setOut(original);
        }
    }

    @Test
    void soleAdministratorGetsATemporaryPasswordAndTheOldOneStopsWorking() throws IOException {
        String session = installAdmin();

        Run run = run("reset-password", "--sole-admin", "--yes", "--json");

        assertThat(run.code()).isZero();
        JsonNode result = TestSupport.MAPPER.readTree(run.output().lines().filter(l -> l.startsWith("{"))
                .reduce((a, b) -> b).orElseThrow());
        assertThat(result.path("username").asText()).isEqualTo("admin");
        String temporary = result.path("temporaryPassword").asText();
        assertThat(temporary).hasSizeGreaterThanOrEqualTo(16);

        Main.Application application = open();
        try {
            assertThatThrownBy(() -> application.auth.login("admin", FORGOTTEN.toCharArray(), LOOPBACK));
            // Sessions ouvertes fermées : la récupération ne laisse pas un accès en place.
            assertThatThrownBy(() -> application.auth.authenticate(session, LOOPBACK));
            var login = application.auth.login("admin", temporary.toCharArray(), LOOPBACK);
            assertThat(login.user().mustChangePassword()).isTrue();
            assertThat(login.user().role()).isEqualTo(Role.ADMIN);

            // Tracée, avec le poste d'où la commande a été lancée, et sans le mot de passe.
            assertThat(application.audit.all()).anySatisfy(event -> {
                assertThat(event.action()).isEqualTo("ADMIN_RECOVERY");
                assertThat(event.actor()).startsWith("cli:");
            }).allSatisfy(event -> assertThat(String.valueOf(event.details())).doesNotContain(temporary));
            assertThat(application.audit.verify().intact()).isTrue();
        } finally {
            application.database.close();
        }
        // Le mot de passe n'est écrit dans aucun fichier du dossier de données (journaux compris).
        try (Stream<Path> files = Files.walk(dataDir)) {
            assertThat(files.filter(Files::isRegularFile).filter(p -> p.toString().endsWith(".log")))
                    .allSatisfy(log -> assertThat(Files.readString(log)).doesNotContain(temporary));
        }
    }

    @Test
    void withoutConfirmationNothingChanges() {
        installAdmin();

        // Pas de terminal dans les tests : sans --yes, la commande refuse au lieu de supposer.
        Run run = run("reset-password", "admin");

        assertThat(run.code()).isEqualTo(CommandLine.EXIT_USAGE);
        Main.Application application = open();
        try {
            assertThat(application.auth.login("admin", FORGOTTEN.toCharArray(), LOOPBACK).token()).isNotBlank();
            assertThat(application.audit.all()).extracting(AuditEvent::action).doesNotContain("ADMIN_RECOVERY");
        } finally {
            application.database.close();
        }
    }

    @Test
    void severalAdministratorsOrUnknownAccountAreRefused() {
        installAdmin();
        Main.Application application = open();
        try {
            var admin = application.auth.authenticate(
                    application.auth.login("admin", FORGOTTEN.toCharArray(), LOOPBACK).token(), LOOPBACK).actor();
            application.users.create(admin, "second", "Second", null, Role.ADMIN);
        } finally {
            application.database.close();
        }

        assertThat(run("reset-password", "--sole-admin", "--yes").output()).contains("Plusieurs administrateurs");
        assertThat(run("reset-password", "personne", "--yes").code()).isEqualTo(CommandLine.EXIT_FAILURE);
        assertThat(run("reset-password").code()).isEqualTo(CommandLine.EXIT_USAGE);
    }
}
