package com.chiffrium.infrastructure.npm;

import com.chiffrium.application.port.ProjectScanner.ScanResult;
import com.chiffrium.application.port.SourcePreparer;
import com.chiffrium.domain.model.ProjectModule;
import com.chiffrium.infrastructure.process.ProcessRunner;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.function.BooleanSupplier;

/**
 * Projets JavaScript sans fichier de verrouillage : sans lui, cdxgen ne connaît que des plages de versions
 * ("^1.2.0") et la recherche de vulnérabilités est imprécise. On résout donc l'arbre exact avec
 * {@code npm install --package-lock-only}, qui n'installe rien et n'écrit que package-lock.json.
 *
 * <p>Garde-fous : aucun script de cycle de vie n'est exécuté ({@code --ignore-scripts}), le registre est
 * imposé en ligne de commande (un .npmrc malveillant du dépôt ne peut pas le rediriger), pas d'audit ni de
 * télémétrie, délai borné, et uniquement sur des clones jetables.
 */
public final class NpmLockfileGenerator implements SourcePreparer {

    static final String MANIFEST = "package.json";
    /** Fichiers de verrouillage reconnus par cdxgen : leur présence rend la génération inutile. */
    static final List<String> LOCKFILES = List.of("package-lock.json", "npm-shrinkwrap.json", "yarn.lock",
            "pnpm-lock.yaml", "bun.lock", "bun.lockb");

    private final ProcessRunner runner;
    private final String npmCommand;
    private final String registry;
    private final Duration timeout;
    private final BooleanSupplier enabled;

    public NpmLockfileGenerator(ProcessRunner runner, String npmCommand, String registry, Duration timeout,
                                BooleanSupplier enabled) {
        this.runner = runner;
        this.npmCommand = npmCommand;
        this.registry = registry;
        this.timeout = timeout;
        this.enabled = enabled;
    }

    @Override
    public String name() {
        return "verrous npm";
    }

    @Override
    public List<String> prepare(Path root, ScanResult scan) {
        List<String> notes = new ArrayList<>();
        if (!enabled.getAsBoolean()) {
            return notes;
        }
        for (ProjectModule module : scan.modules()) {
            if (!module.manifests().contains(MANIFEST)) {
                continue;
            }
            Path dir = root.resolve(module.path()).normalize();
            if (!dir.startsWith(root) || LOCKFILES.stream().anyMatch(lock -> Files.exists(dir.resolve(lock)))) {
                continue;
            }
            ProcessRunner.Result result;
            try {
                result = runner.run(command(), dir, Map.of(), timeout, "npm lockfile " + module.path());
            } catch (IOException e) {
                notes.add("npm introuvable (" + npmCommand + ") : fichiers de verrouillage non générés.");
                return notes;
            }
            notes.add(result.succeeded()
                    ? "package-lock.json généré pour " + module.path() + " (versions exactes des dépendances)."
                    : "Génération de package-lock.json impossible pour " + module.path()
                    + (result.timedOut() ? " (délai dépassé)" : "") + " : versions approximatives.");
        }
        return notes;
    }

    List<String> command() {
        return List.of(npmCommand, "install", "--package-lock-only", "--ignore-scripts", "--no-audit", "--no-fund",
                "--registry=" + registry);
    }
}
