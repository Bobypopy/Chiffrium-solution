package com.chiffrium.infrastructure.git;

import com.chiffrium.application.port.AnalysisException;
import com.chiffrium.application.port.HistoryScanner;
import com.chiffrium.domain.model.SecurityFinding;
import com.chiffrium.infrastructure.findings.SecurityFindingDetector;
import com.chiffrium.infrastructure.scan.FileClassifier;
import org.eclipse.jgit.lib.Constants;
import org.eclipse.jgit.lib.FileMode;
import org.eclipse.jgit.lib.ObjectId;
import org.eclipse.jgit.lib.ObjectLoader;
import org.eclipse.jgit.lib.ObjectReader;
import org.eclipse.jgit.lib.Repository;
import org.eclipse.jgit.revwalk.RevCommit;
import org.eclipse.jgit.revwalk.RevTree;
import org.eclipse.jgit.revwalk.RevWalk;
import org.eclipse.jgit.storage.file.FileRepositoryBuilder;
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
 * Historique Git lu avec JGit, sans rien exécuter du dépôt. Chaque commit de la branche analysée est comparé à
 * son premier parent ; seules les versions de fichiers qui n'existent pas dans l'état actuel sont relues (le
 * reste a déjà été analysé), avec les mêmes filtres que le parcours du projet (dossiers ignorés, taille).
 * Un même secret retrouvé dans plusieurs commits donne un seul constat, au commit le plus récent.
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
            return scan(repository, prefix(repository, root));
        } catch (IOException e) {
            throw new AnalysisException("Lecture de l'historique Git impossible : " + e.getMessage(), e);
        }
    }

    private HistoryResult scan(Repository repository, String prefix) throws IOException {
        ObjectId head = repository.resolve(Constants.HEAD);
        if (head == null) {
            return new HistoryResult(List.of(), List.of("Historique Git vide : le dépôt n'a aucun commit."));
        }
        List<String> warnings = new ArrayList<>();
        if (Files.exists(repository.getDirectory().toPath().resolve(SHALLOW_FILE))) {
            warnings.add("Historique Git partiel (clone superficiel) : seuls les commits récupérés sont analysés.");
        }
        Map<String, SecurityFinding> findings = new LinkedHashMap<>();
        try (RevWalk walk = new RevWalk(repository); ObjectReader reader = repository.newObjectReader()) {
            RevCommit start = walk.parseCommit(head);
            Set<ObjectId> seen = blobsOf(reader, start.getTree());
            walk.markStart(start);
            int commits = 0;
            for (RevCommit commit : walk) {
                if (Thread.currentThread().isInterrupted()) {
                    break;
                }
                if (++commits > maxCommits) {
                    warnings.add("Historique Git tronqué : les " + maxCommits + " commits les plus récents sont analysés.");
                    break;
                }
                for (SecurityFinding finding : changedFindings(walk, reader, commit, prefix, seen)) {
                    findings.putIfAbsent(HistoryScanner.sameSecret(finding), finding);
                }
            }
        }
        return new HistoryResult(List.copyOf(findings.values()), warnings);
    }

    /** Constats des fichiers ajoutés ou modifiés par un commit, dans des versions encore jamais lues. */
    private List<SecurityFinding> changedFindings(RevWalk walk, ObjectReader reader, RevCommit commit, String prefix,
                                                  Set<ObjectId> seen) throws IOException {
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
                String relative = path.substring(prefix.length());
                ObjectId blob = tree.getObjectId(1);
                if (!isAnalysable(relative) || !seen.add(blob)) {
                    continue;
                }
                ObjectLoader content = reader.open(blob);
                if (content.getSize() <= maxFileBytes) {
                    result.addAll(detector.historyFindings(relative, content.getBytes(), commit.getName()));
                }
            }
        }
        return result;
    }

    /** Versions de fichiers de l'état actuel : déjà analysées par le parcours du projet. */
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
        String name = segments[segments.length - 1];
        return FileClassifier.languageOf(name).isPresent() || FileClassifier.isMaterial(name) || FileClassifier.isData(name);
    }

    /** Préfixe du dossier analysé dans le dépôt ("" à la racine, "services/api/" pour un sous-dossier). */
    private static String prefix(Repository repository, Path root) throws IOException {
        Path workTree = repository.getWorkTree().toPath().toRealPath();
        String relative = workTree.relativize(root.toRealPath()).toString().replace('\\', '/');
        return relative.isEmpty() ? "" : relative + "/";
    }
}
