package com.chiffrium;

import com.chiffrium.application.AnalysisService;
import com.chiffrium.application.security.Actor;
import com.chiffrium.application.security.UserService;
import com.chiffrium.domain.security.Role;
import com.chiffrium.domain.security.User;
import com.chiffrium.domain.model.AnalysisJob;
import com.chiffrium.domain.model.AnalysisReport;
import com.chiffrium.domain.model.AnalysisRequest;
import com.chiffrium.domain.model.CryptoAsset;
import com.chiffrium.domain.model.PolicyStatus;
import com.chiffrium.infrastructure.db.Database;
import com.chiffrium.infrastructure.db.DatabaseMigrator;
import com.chiffrium.infrastructure.sarif.SarifReportExporter;
import org.slf4j.MDC;

import java.io.PrintStream;
import java.nio.file.Path;
import java.sql.SQLException;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;

/**
 * Mode ligne de commande :
 * <pre>
 * java -jar chiffrium-backend.jar analyze &lt;url|chemin&gt; [--no-cdxgen] [--no-vulns] [--history]
 *      [--branch nom] [--fail-on disallowed|deprecated] [--sarif fichier]
 * java -jar chiffrium-backend.jar migrate-db --to &lt;url jdbc&gt; [--user u] [--password p] [--force]
 * java -jar chiffrium-backend.jar reset-password &lt;identifiant&gt;|--sole-admin [--yes] [--json]
 * </pre>
 * La première intègre l'analyse dans une chaîne CI/CD, la deuxième recopie la base locale vers PostgreSQL, la
 * troisième rend l'accès à un compte local dont le mot de passe est perdu (dernier administrateur compris).
 * Codes de sortie : 0 succès, 1 seuil de politique dépassé, 2 usage incorrect, 3 échec.
 */
final class CommandLine {

    static final int EXIT_OK = 0;
    static final int EXIT_POLICY_VIOLATION = 1;
    static final int EXIT_USAGE = 2;
    static final int EXIT_FAILURE = 3;
    private static final String USAGE = "Usage : analyze <url|chemin> [--no-cdxgen] [--no-vulns] [--history] "
            + "[--branch nom] [--fail-on disallowed|deprecated] [--sarif fichier]";
    private static final String MIGRATE_USAGE =
            "Usage : migrate-db --to <url jdbc> [--user utilisateur] [--password mot de passe] [--force]";
    private static final String RESET_USAGE = "Usage : reset-password <identifiant>|--sole-admin [--yes] [--json]";
    static final String COMMAND_ANALYZE = "analyze";
    static final String COMMAND_MIGRATE = "migrate-db";
    static final String COMMAND_RESET_PASSWORD = "reset-password";
    /** Demandeur enregistré pour les analyses lancées en ligne de commande (traçabilité). */
    static final String CLI_ACTOR = "cli";

    private final Main.Application application;
    private final PrintStream out = System.out;

    CommandLine(Main.Application application) {
        this.application = application;
    }

    /** Vrai si le premier argument désigne une commande à exécuter sans démarrer le serveur. */
    static boolean handles(String command) {
        return COMMAND_ANALYZE.equals(command) || COMMAND_MIGRATE.equals(command)
                || COMMAND_RESET_PASSWORD.equals(command);
    }

    int run(String[] args) {
        if (args.length > 0 && COMMAND_MIGRATE.equals(args[0])) {
            return migrate(args);
        }
        if (args.length > 0 && COMMAND_RESET_PASSWORD.equals(args[0])) {
            return resetPassword(args);
        }
        if (args.length < 2) {
            out.println(USAGE);
            return EXIT_USAGE;
        }
        String target = args[1];
        boolean runCdxgen = true;
        boolean scanVulnerabilities = true;
        boolean scanGitHistory = false;
        String branch = null;
        PolicyStatus failOn = null;
        Path sarif = null;
        for (int i = 2; i < args.length; i++) {
            switch (args[i]) {
                case "--no-cdxgen" -> runCdxgen = false;
                case "--no-vulns" -> scanVulnerabilities = false;
                case "--history" -> scanGitHistory = true;
                case "--branch" -> branch = i + 1 < args.length ? args[++i] : null;
                case "--fail-on" -> failOn = i + 1 < args.length
                        ? PolicyStatus.fromId(args[++i].toUpperCase(Locale.ROOT)) : null;
                case "--sarif" -> sarif = i + 1 < args.length ? Path.of(args[++i]) : null;
                default -> {
                    out.println("Option inconnue : " + args[i] + System.lineSeparator() + USAGE);
                    return EXIT_USAGE;
                }
            }
        }
        AnalysisRequest request = new AnalysisRequest(target, branch, true, runCdxgen, scanVulnerabilities, null,
                scanGitHistory);
        AnalysisJob job = AnalysisJob.queued(UUID.randomUUID().toString(), request, CLI_ACTOR,
                application.clock.instant()).started(application.clock.instant());
        application.audit.record(Actor.SYSTEM, "ANALYSIS_SUBMITTED", job.id(), target + " (ligne de commande)");
        MDC.put(AnalysisService.MDC_ANALYSIS_ID, job.id());
        try {
            AnalysisReport report = application.pipeline.run(job, step -> out.println("... " + step), metric -> { });
            application.repository.save(job.succeeded(report.summary(), application.clock.instant()));
            printSummary(report);
            // Les artefacts de l'analyse sont chiffrés sur disque : le SARIF demandé (revue de code, GitHub code
            // scanning) est écrit en clair, à l'endroit indiqué.
            if (sarif != null) {
                new SarifReportExporter(application.mapper).export(report, sarif);
                out.println("SARIF : " + sarif.toAbsolutePath());
            }
            return exceedsThreshold(report, failOn) ? EXIT_POLICY_VIOLATION : EXIT_OK;
        } catch (RuntimeException e) {
            out.println("Échec de l'analyse : " + e.getMessage());
            application.repository.save(job.failed(e.getMessage(), application.clock.instant()));
            return EXIT_FAILURE;
        } finally {
            MDC.remove(AnalysisService.MDC_ANALYSIS_ID);
            application.repository.seal(job.id(), application.settings.current().storage().keepRawOutputs());
            application.database.close();
        }
    }

    /**
     * Recopie la base courante vers une autre (typiquement H2 -> PostgreSQL).
     *
     * <p>On ne touche jamais à la base d'origine : en cas d'échec, il suffit de relancer l'application comme
     * avant. La cible doit être vide, sauf {@code --force}.
     */
    private int migrate(String[] args) {
        String url = null;
        String user = null;
        String password = null;
        boolean force = false;
        for (int i = 1; i < args.length; i++) {
            switch (args[i]) {
                case "--to" -> url = i + 1 < args.length ? args[++i] : null;
                case "--user" -> user = i + 1 < args.length ? args[++i] : null;
                case "--password" -> password = i + 1 < args.length ? args[++i] : null;
                case "--force" -> force = true;
                default -> {
                    out.println("Option inconnue : " + args[i] + System.lineSeparator() + MIGRATE_USAGE);
                    return EXIT_USAGE;
                }
            }
        }
        if (url == null || url.isBlank()) {
            out.println(MIGRATE_USAGE);
            return EXIT_USAGE;
        }
        out.println("Base d'origine : " + application.config.databaseUrl()
                .orElseGet(() -> "H2 " + application.config.databaseFile()));
        out.println("Base cible     : " + url);
        try (Database target = Database.postgresql(url, user, password)) {
            DatabaseMigrator.Result result = DatabaseMigrator.copy(application.database, target, force);
            for (DatabaseMigrator.TableResult table : result.tables()) {
                out.printf("  %-20s %6d ligne(s)%n", table.table(), table.rows());
            }
            out.printf("%n%d ligne(s) copiée(s).%n", result.total());
            out.println("Pour utiliser la nouvelle base, démarrez l'application avec CHIFFRIUM_DB_URL="
                    + url + (user != null ? " et CHIFFRIUM_DB_USER=" + user : "") + '.');
            out.println("Pensez à recopier le dossier de données (rapports, artefacts) et la clé maîtresse : "
                    + "sans elle, les réglages chiffrés et les artefacts ne sont plus lisibles.");
            application.audit.record(Actor.SYSTEM, "DATABASE_MIGRATED", url,
                    result.total() + " ligne(s) copiée(s) (ligne de commande)");
            return EXIT_OK;
        } catch (IllegalStateException e) {
            out.println("Migration refusée : " + e.getMessage());
            return EXIT_FAILURE;
        } catch (SQLException | RuntimeException e) {
            out.println("Échec de la migration : " + e.getMessage());
            out.println("La base d'origine n'a pas été modifiée.");
            return EXIT_FAILURE;
        } finally {
            application.database.close();
        }
    }

    /**
     * Mot de passe provisoire pour un compte local, quand plus personne ne peut se connecter pour le faire depuis
     * l'interface (seul administrateur, sans SSO). Même effet qu'une réinitialisation par un administrateur :
     * changement imposé à la connexion suivante, verrouillage levé, sessions fermées, action tracée.
     *
     * <p>Sécurité : la commande ouvre la base avec la clé maîtresse, donc seul celui qui a déjà accès aux données
     * (session Windows du poste pour l'application de bureau, accès au serveur et à sa clé sinon) peut la lancer ;
     * rien n'est exposé sur le réseau. Le mot de passe n'est écrit que sur la sortie standard, jamais dans le
     * journal ni dans l'audit.
     */
    private int resetPassword(String[] args) {
        String username = null;
        boolean soleAdmin = false;
        boolean confirmed = false;
        boolean json = false;
        for (int i = 1; i < args.length; i++) {
            switch (args[i]) {
                case "--sole-admin" -> soleAdmin = true;
                case "--yes" -> confirmed = true;
                case "--json" -> json = true;
                default -> {
                    if (args[i].startsWith("--") || username != null) {
                        out.println("Option inconnue : " + args[i] + System.lineSeparator() + RESET_USAGE);
                        return EXIT_USAGE;
                    }
                    username = args[i];
                }
            }
        }
        if ((username == null) == !soleAdmin) {
            out.println(RESET_USAGE);
            return EXIT_USAGE;
        }
        try {
            Actor actor = new Actor(null, cliOperator(), Role.ADMIN, null);
            List<User> accounts = application.users.list(actor);
            String wanted = username;
            List<User> targets = soleAdmin
                    ? accounts.stream().filter(u -> u.role() == Role.ADMIN && u.enabled() && u.source() == User.Source.LOCAL)
                    .toList()
                    : accounts.stream().filter(u -> u.username().equals(wanted)).toList();
            if (targets.size() != 1) {
                out.println(soleAdmin
                        ? targets.isEmpty() ? "Aucun administrateur local actif."
                        : "Plusieurs administrateurs locaux : l'un d'eux peut réinitialiser ce mot de passe depuis "
                        + "Administration > Comptes."
                        : "Compte introuvable : " + username);
                return EXIT_FAILURE;
            }
            User target = targets.get(0);
            if (!confirmed && !confirm(target.username())) {
                out.println("Réinitialisation annulée.");
                return EXIT_USAGE;
            }
            UserService.UserWithPassword reset = application.users.resetPassword(actor, target.id());
            application.audit.record(actor, "ADMIN_RECOVERY", target.username(),
                    "mot de passe réinitialisé hors connexion (ligne de commande)");
            if (json) {
                out.println(application.mapper.writeValueAsString(Map.of("username", target.username(),
                        "temporaryPassword", reset.temporaryPassword())));
            } else {
                out.println("Mot de passe provisoire de " + target.username() + " : " + reset.temporaryPassword());
                out.println("Affiché une seule fois ; il devra être changé à la prochaine connexion.");
            }
            return EXIT_OK;
        } catch (IllegalArgumentException | com.fasterxml.jackson.core.JsonProcessingException e) {
            out.println("Réinitialisation impossible : " + e.getMessage());
            return EXIT_FAILURE;
        } finally {
            application.database.close();
        }
    }

    /** Confirmation tapée par une personne : sans terminal, la commande exige --yes plutôt que de supposer. */
    private boolean confirm(String username) {
        java.io.Console console = System.console();
        if (console == null) {
            out.println("Confirmation impossible sans terminal : relancer avec --yes.");
            return false;
        }
        String typed = console.readLine("Retaper l'identifiant \"%s\" pour confirmer la réinitialisation : ", username);
        return username.equals(typed == null ? null : typed.trim());
    }

    /** Auteur inscrit à l'audit : compte système et poste d'où la commande a été lancée. */
    private static String cliOperator() {
        String host;
        try {
            host = java.net.InetAddress.getLocalHost().getHostName();
        } catch (java.net.UnknownHostException e) {
            host = "poste inconnu";
        }
        return CLI_ACTOR + ":" + System.getProperty("user.name", "?") + "@" + host;
    }

    private void printSummary(AnalysisReport report) {
        out.printf("%nAnalyse %s%n", report.analysisId());
        out.printf("Score : %d/100 | actifs : %d | vulnérables quantique : %d | CVE dépendances : %d%n",
                report.summary().score(), report.summary().totalAssets(), report.summary().quantumVulnerable(),
                report.summary().vulnerabilities());
        for (CryptoAsset asset : report.assets()) {
            if (asset.verdict() != null && asset.verdict().status().isProblematic()) {
                out.printf("  [%s] %s (%d occurrence(s))%n", asset.verdict().status().id(), asset.name(),
                        asset.occurrences().size());
            }
        }
        out.printf("Rapport : %s%n", application.config.analysesDir().resolve(report.analysisId()));
    }

    private static boolean exceedsThreshold(AnalysisReport report, PolicyStatus failOn) {
        if (failOn == null) {
            return false;
        }
        return report.assets().stream()
                .anyMatch(a -> a.verdict() != null && a.verdict().status().ordinal() >= failOn.ordinal());
    }
}
