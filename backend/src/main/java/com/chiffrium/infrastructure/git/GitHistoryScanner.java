package com.chiffrium.infrastructure.git;

import com.chiffrium.application.port.AnalysisException;
import com.chiffrium.application.port.HistoryScanner;
import com.chiffrium.domain.model.SecurityFinding;
import com.chiffrium.infrastructure.findings.SecurityFindingDetector;
import com.chiffrium.infrastructure.scan.FileClassifier;
import org.eclipse.jgit.errors.MissingObjectException;
import org.eclipse.jgit.lib.Constants;
import org.eclipse.jgit.lib.FileMode;
import org.eclipse.jgit.lib.ObjectId;
import org.eclipse.jgit.lib.ObjectLoader;
import org.eclipse.jgit.lib.ObjectReader;
import org.eclipse.jgit.lib.Ref;
import org.eclipse.jgit.lib.Repository;
import org.eclipse.jgit.revwalk.RevCommit;
import org.eclipse.jgit.revwalk.RevObject;
import org.eclipse.jgit.revwalk.RevTree;
import org.eclipse.jgit.revwalk.RevWalk;
import org.eclipse.jgit.storage.file.FileRepositoryBuilder;
import org.eclipse.jgit.submodule.SubmoduleWalk;
import org.eclipse.jgit.treewalk.EmptyTreeIterator;
import org.eclipse.jgit.treewalk.TreeWalk;
import org.eclipse.jgit.treewalk.filter.TreeFilter;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Historique Git lu avec JGit, sans rien exécuter du dépôt : toutes les branches et tous les tags, puis les
 * sous-modules récupérés. Chaque commit est comparé à son premier parent ; seules les versions de fichiers qui
 * n'existent pas dans l'état analysé sont relues (le reste a déjà été analysé), avec les mêmes filtres que le
 * parcours du projet (dossiers ignorés, taille). Un même secret retrouvé dans plusieurs commits donne un seul
 * constat, au commit le plus récent.
 */
public final class GitHistoryScanner implements HistoryScanner {

    static final int MAX_COMMITS = 10_000;
    private static final String SHALLOW_FILE = "shallow";

    private final SecurityFindingDetector detector;
    private final long maxFileBytes;
    private final int maxCommits;

    public GitHistoryScanner(SecurityFindingDetector detector, long maxFileBytes) {
        this(detector, maxFileBytes, MAX_COMMITS);
    }

    GitHistoryScanner(SecurityFindingDetector detector, long maxFileBytes, int maxCommits) {
        this.detector = detector;
        this.maxFileBytes = maxFileBytes;
        this.maxCommits = maxCommits;
    }

    @Override
    public HistoryResult scan(Path root) {
        FileRepositoryBuilder builder = new FileRepositoryBuilder().findGitDir(root.toFile());
        if (builder.getGitDir() == null) {
            return new HistoryResult(List.of(), List.of("Historique Git non analysé : le dossier n'est pas un dépôt Git."));
        }
        try (Repository repository = builder.setMustExist(true).build()) {
            Scan scan = new Scan();
            String prefix = prefix(repository, root);
            scanRepository(repository, prefix, "", scan);
            scanSubmodules(repository, prefix, "", scan);
            return new HistoryResult(List.copyOf(scan.findings.values()), scan.warnings);
        } catch (IOException e) {
            throw new AnalysisException("Lecture de l'historique Git impossible : " + e.getMessage(), e);
        }
    }

    /** Constats (un par secret) et avertissements accumulés sur le dépôt et ses sous-modules. */
    private static final class Scan {
        private final Map<String, SecurityFinding> findings = new LinkedHashMap<>();
        private final List<String> warnings = new ArrayList<>();
    }

    /**
     * @param prefix      dossier analysé dans ce dépôt ("" pour tout le dépôt)
     * @param displayPath chemin de ce dépôt dans le projet analysé ("" ou "libs/sous-module/"), en tête des constats
     */
    private void scanRepository(Repository repository, String prefix, String displayPath, Scan scan)
            throws IOException {
        ObjectId head = repository.resolve(Constants.HEAD);
        if (head == null) {
            scan.warnings.add("Historique Git vide : le dépôt n'a aucun commit.");
            return;
        }
        if (Files.exists(repository.getDirectory().toPath().resolve(SHALLOW_FILE))) {
            scan.warnings.add("Historique Git partiel (clone superficiel) : seuls les commits récupérés sont analysés.");
        }
        try (RevWalk walk = new RevWalk(repository); ObjectReader reader = repository.newObjectReader()) {
            RevCommit start = walk.parseCommit(head);
            Set<ObjectId> seen = blobsOf(reader, start.getTree());
            walk.markStart(start);
            // Une clé poussée sur une autre branche, ou figée dans un tag, reste lisible par qui clone le dépôt.
            for (Ref ref : repository.getRefDatabase().getRefs()) {
                markStart(walk, ref);
            }
            int commits = 0;
            for (RevCommit commit : walk) {
                if (Thread.currentThread().isInterrupted()) {
                    break;
                }
                if (++commits > maxCommits) {
                    scan.warnings.add("Historique Git tronqué : les " + maxCommits
                            + " commits les plus récents sont analysés.");
                    break;
                }
                for (SecurityFinding finding : changedFindings(walk, reader, commit, prefix, displayPath, seen)) {
                    scan.findings.putIfAbsent(HistoryScanner.sameSecret(finding), finding);
                }
            }
        }
    }

    /** Départ du parcours : commit d'une branche ou désigné par un tag ; une référence cassée est ignorée. */
    private static void markStart(RevWalk walk, Ref ref) throws IOException {
        if (ref.getObjectId() == null) {
            return;
        }
        try {
            RevObject target = walk.peel(walk.parseAny(ref.getObjectId()));
            if (target instanceof RevCommit commit) {
                walk.markStart(commit);
            }
        } catch (MissingObjectException e) {
            // Référence vers un objet absent (dépôt incomplet) : rien à parcourir.
        }
    }

    /** Sous-modules récupérés (clonés avec le dépôt ou initialisés dans le dossier local), récursivement. */
    private void scanSubmodules(Repository repository, String prefix, String displayPath, Scan scan)
            throws IOException {
        try (SubmoduleWalk submodules = SubmoduleWalk.forIndex(repository)) {
            while (submodules.next()) {
                String path = submodules.getPath() + "/";
                if (!path.startsWith(prefix)) {
                    continue;
                }
                try (Repository submodule = submodules.getRepository()) {
                    if (submodule != null) {
                        String subPath = displayPath + path.substring(prefix.length());
                        scanRepository(submodule, "", subPath, scan);
                        scanSubmodules(submodule, "", subPath, scan);
                    }
                }
            }
        }
    }

    /** Constats des fichiers ajoutés ou modifiés par un commit, dans des versions encore jamais lues. */
    private List<SecurityFinding> changedFindings(RevWalk walk, ObjectReader reader, RevCommit commit, String prefix,
                                                  String displayPath, Set<ObjectId> seen) throws IOException {
        List<SecurityFinding> result = new ArrayList<>();
        try (TreeWalk tree = new TreeWalk(reader)) {
            if (commit.getParentCount() > 0) {
                tree.addTree(walk.parseCommit(commit.getParent(0)).getTree());
            } else {
                tree.addTree(new EmptyTreeIterator());
            }
            tree.addTree(commit.getTree());
            tree.setRecursive(true);
            tree.setFilter(TreeFilter.ANY_DIFF);
            while (tree.next()) {
                FileMode mode = tree.getFileMode(1);
                String path = tree.getPathString();
                if (mode != FileMode.REGULAR_FILE && mode != FileMode.EXECUTABLE_FILE || !path.startsWith(prefix)) {
                    continue;
                }
                String shown = displayPath + path.substring(prefix.length());
                ObjectId blob = tree.getObjectId(1);
                if (!isAnalysable(shown) || !seen.add(blob)) {
                    continue;
                }
                ObjectLoader content = reader.open(blob);
                if (content.getSize() <= maxFileBytes) {
                    result.addAll(detector.historyFindings(shown, content.getBytes(), commit.getName()));
                }
            }
        }
        return result;
    }

    /** Versions de fichiers de l'état analysé : déjà analysées par le parcours du projet. */
    private static Set<ObjectId> blobsOf(ObjectReader reader, RevTree tree) throws IOException {
        Set<ObjectId> blobs = new HashSet<>();
        try (TreeWalk walk = new TreeWalk(reader)) {
            walk.addTree(tree);
            walk.setRecursive(true);
            while (walk.next()) {
                blobs.add(walk.getObjectId(0));
            }
        }
        return blobs;
    }

    /** Mêmes fichiers que le parcours du projet : dossiers ignorés exclus, langage, matériel ou données. */
    private static boolean isAnalysable(String path) {
        String[] segments = path.split("/");
        if (Arrays.stream(segments, 0, segments.length - 1).anyMatch(FileClassifier::isIgnoredDirectory)) {
            return false;
        }
        return FileClassifier.isScanned(segments[segments.length - 1]);
    }

    /** Préfixe du dossier analysé dans le dépôt ("" à la racine, "services/api/" pour un sous-dossier). */
    private static String prefix(Repository repository, Path root) throws IOException {
        Path workTree = repository.getWorkTree().toPath().toRealPath();
        String relative = workTree.relativize(root.toRealPath()).toString().replace('\\', '/');
        return relative.isEmpty() ? "" : relative + "/";
    }
}
