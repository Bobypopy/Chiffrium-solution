package com.chiffrium.infrastructure.git;

import com.chiffrium.application.port.AnalysisException;
import com.chiffrium.application.port.SourceFetcher;
import com.chiffrium.domain.model.AnalysisRequest;
import org.eclipse.jgit.api.CloneCommand;
import org.eclipse.jgit.api.Git;
import org.eclipse.jgit.api.errors.GitAPIException;
import org.eclipse.jgit.lib.ObjectId;
import org.eclipse.jgit.transport.UsernamePasswordCredentialsProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.regex.Pattern;

/**
 * Récupère le code source :
 * <ul>
 *   <li>URL {@code https://} : clonage JGit (sous-modules récursifs en option, profondeur configurable) ;</li>
 *   <li>chemin local : accepté uniquement sous une racine autorisée (ALLOWED_LOCAL_ROOTS).</li>
 * </ul>
 * Les URL contenant des identifiants sont refusées (ils finiraient dans les logs) : utiliser GIT_TOKEN.
 */
public final class GitSourceFetcher implements SourceFetcher {

    private static final Logger LOG = LoggerFactory.getLogger(GitSourceFetcher.class);
    private static final String HTTPS = "https";
    private static final String SOURCE_DIR = "source";
    private static final Pattern BRANCH_PATTERN = Pattern.compile("[A-Za-z0-9._/-]{1,200}");
    private static final String REFS_HEADS = "refs/heads/";

    private final List<Path> allowedLocalRoots;
    private final List<String> allowedGitHosts;
    private final int cloneDepth;
    private final Duration timeout;
    private final String gitUsername;
    private final Optional<String> gitToken;

    public GitSourceFetcher(List<Path> allowedLocalRoots, List<String> allowedGitHosts, int cloneDepth,
                            Duration timeout, String gitUsername, Optional<String> gitToken) {
        this.allowedLocalRoots = List.copyOf(allowedLocalRoots);
        this.allowedGitHosts = allowedGitHosts.stream().map(h -> h.toLowerCase(Locale.ROOT)).toList();
        this.cloneDepth = cloneDepth;
        this.timeout = timeout;
        this.gitUsername = gitUsername;
        this.gitToken = gitToken;
    }

    public static boolean looksLikeUrl(String target) {
        return target != null && target.contains("://");
    }

    @Override
    public FetchedSource fetch(AnalysisRequest request, Path workspace) {
        String target = request.target() == null ? "" : request.target().trim();
        if (target.isEmpty()) {
            throw new AnalysisException("La cible (URL Git ou chemin) est obligatoire.");
        }
        return looksLikeUrl(target) ? cloneRepository(target, request, workspace) : resolveLocal(target);
    }

    private FetchedSource cloneRepository(String url, AnalysisRequest request, Path workspace) {
        URI uri = validateUrl(url);
        String branch = request.branch() == null || request.branch().isBlank() ? null : request.branch().trim();
        if (branch != null && (!BRANCH_PATTERN.matcher(branch).matches() || branch.contains(".."))) {
            throw new AnalysisException("Nom de branche invalide : " + branch);
        }
        Path destination = workspace.resolve(SOURCE_DIR);
        LOG.info("Clonage de {} (branche {}, profondeur {}, sous-modules {})", uri, branch == null ? "par défaut" : branch,
                cloneDepth == 0 ? "complète" : cloneDepth, request.recurseSubmodules());

        CloneCommand clone = Git.cloneRepository()
                .setURI(uri.toString())
                .setDirectory(destination.toFile())
                .setCloneSubmodules(request.recurseSubmodules())
                .setTimeout((int) timeout.toSeconds())
                // Arrêt de l'analyse : le clonage s'interrompt dès que le thread est interrompu.
                .setProgressMonitor(new InterruptibleMonitor());
        if (cloneDepth > 0) {
            clone.setDepth(cloneDepth);
        }
        if (branch != null) {
            clone.setBranch(REFS_HEADS + branch);
        }
        gitToken.ifPresent(token -> clone.setCredentialsProvider(new UsernamePasswordCredentialsProvider(gitUsername, token)));

        try (Git git = clone.call()) {
            ObjectId head = git.getRepository().resolve("HEAD");
            String resolvedBranch = git.getRepository().getBranch();
            LOG.info("Clonage terminé : {} @ {}", resolvedBranch, head == null ? "?" : head.name());
            return new FetchedSource(destination, "git", resolvedBranch, head == null ? null : head.name());
        } catch (GitAPIException | IOException e) {
            throw new AnalysisException("Échec du clonage de " + uri + " : " + e.getMessage(), e);
        }
    }

    /** Moniteur sans affichage dont seule l'annulation compte (interruption du thread de l'analyse). */
    private static final class InterruptibleMonitor extends org.eclipse.jgit.lib.EmptyProgressMonitor {
        @Override
        public boolean isCancelled() {
            return Thread.currentThread().isInterrupted();
        }
    }

    URI validateUrl(String url) {
        URI uri;
        try {
            uri = new URI(url);
        } catch (URISyntaxException e) {
            throw new AnalysisException("URL Git invalide : " + url, e);
        }
        if (!HTTPS.equalsIgnoreCase(uri.getScheme())) {
            throw new AnalysisException("Seules les URL https:// sont acceptées (reçu : " + uri.getScheme() + ").");
        }
        if (uri.getHost() == null || uri.getHost().isBlank()) {
            throw new AnalysisException("URL Git sans hôte : " + url);
        }
        if (uri.getUserInfo() != null) {
            throw new AnalysisException("Les identifiants dans l'URL sont interdits : configurer GIT_TOKEN côté serveur.");
        }
        String host = uri.getHost().toLowerCase(Locale.ROOT);
        if (!allowedGitHosts.isEmpty() && !allowedGitHosts.contains(host)) {
            throw new AnalysisException("Hôte Git non autorisé : " + host + " (autorisés : " + allowedGitHosts + ").");
        }
        return uri;
    }

    FetchedSource resolveLocal(String target) {
        if (allowedLocalRoots.isEmpty()) {
            throw new AnalysisException("L'analyse de dossiers locaux est désactivée (ALLOWED_LOCAL_ROOTS vide).");
        }
        Path path;
        try {
            path = Path.of(target).toAbsolutePath().normalize();
            if (!Files.isDirectory(path)) {
                throw new AnalysisException("Dossier introuvable : " + target);
            }
            path = path.toRealPath();
        } catch (IOException | java.nio.file.InvalidPathException e) {
            throw new AnalysisException("Chemin invalide : " + target, e);
        }
        Path resolved = path;
        boolean allowed = allowedLocalRoots.stream().anyMatch(root -> resolved.startsWith(realOrSelf(root)));
        if (!allowed) {
            throw new AnalysisException("Chemin hors des racines autorisées : " + target);
        }
        return new FetchedSource(resolved, "local", null, null);
    }

    private static Path realOrSelf(Path root) {
        try {
            return root.toRealPath();
        } catch (IOException e) {
            return root;
        }
    }
}
