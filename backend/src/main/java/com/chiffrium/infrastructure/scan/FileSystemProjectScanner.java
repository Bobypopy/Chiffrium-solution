package com.chiffrium.infrastructure.scan;

import com.chiffrium.application.port.AnalysisException;
import com.chiffrium.application.port.ProjectScanner;
import com.chiffrium.domain.model.Language;
import com.chiffrium.domain.model.ProjectModule;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * Parcours récursif du projet. Chaque dossier contenant un manifeste (pom.xml, package.json, go.mod...)
 * ou un dépôt Git (dossier .git ou fichier .git d'un sous-module) devient un module ; chaque fichier est
 * rattaché au module le plus proche. Les liens symboliques ne sont pas suivis (évite boucles et évasion).
 */
public final class FileSystemProjectScanner implements ProjectScanner {

    private static final Logger LOG = LoggerFactory.getLogger(FileSystemProjectScanner.class);
    private static final String GIT_ENTRY = ".git";
    private static final String ROOT_MODULE = ".";
    static final int MAX_DEPTH = 40;
    static final int MAX_FILES = 200_000;

    private final long maxFileBytes;

    public FileSystemProjectScanner(long maxFileBytes) {
        this.maxFileBytes = maxFileBytes;
    }

    @Override
    public ScanResult scan(Path root) {
        Walker walker = new Walker(root);
        try {
            Files.walkFileTree(root, Set.of(), MAX_DEPTH, walker);
        } catch (IOException e) {
            throw new AnalysisException("Parcours impossible de " + root + " : " + e.getMessage(), e);
        }
        if (walker.limitReached) {
            LOG.warn("Limite de {} fichiers atteinte : parcours tronqué", MAX_FILES);
        }
        List<ProjectModule> modules = walker.modules.values().stream().map(ModuleBuilder::build).toList();
        return new ScanResult(modules, walker.files, walker.skipped);
    }

    private final class Walker extends SimpleFileVisitor<Path> {
        private final Path root;
        private final Map<Path, ModuleBuilder> modules = new LinkedHashMap<>();
        private final List<ScannedFile> files = new ArrayList<>();
        private int skipped;
        private boolean limitReached;

        Walker(Path root) {
            this.root = root;
            modules.put(root, new ModuleBuilder(ROOT_MODULE));
        }

        @Override
        public FileVisitResult preVisitDirectory(Path dir, BasicFileAttributes attrs) throws IOException {
            if (!dir.equals(root) && FileClassifier.isIgnoredDirectory(dir.getFileName().toString())) {
                return FileVisitResult.SKIP_SUBTREE;
            }
            boolean gitRepository = Files.exists(dir.resolve(GIT_ENTRY), LinkOption.NOFOLLOW_LINKS);
            List<String> manifests = new ArrayList<>();
            try (var entries = Files.list(dir)) {
                entries.filter(Files::isRegularFile)
                        .map(p -> p.getFileName().toString())
                        .filter(FileClassifier::isManifest)
                        .forEach(manifests::add);
            }
            if (gitRepository || !manifests.isEmpty()) {
                ModuleBuilder module = modules.computeIfAbsent(dir, d -> new ModuleBuilder(relative(d)));
                module.gitRepository |= gitRepository;
                module.manifests.addAll(manifests);
            }
            return FileVisitResult.CONTINUE;
        }

        @Override
        public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) {
            if (!attrs.isRegularFile()) {
                return FileVisitResult.CONTINUE;
            }
            if (files.size() >= MAX_FILES) {
                limitReached = true;
                return FileVisitResult.TERMINATE;
            }
            String name = file.getFileName().toString();
            Optional<Language> language = FileClassifier.languageOf(name);
            boolean material = FileClassifier.isMaterial(name);
            if (language.isEmpty() && !material) {
                return FileVisitResult.CONTINUE;
            }
            if (attrs.size() > maxFileBytes) {
                skipped++;
                return FileVisitResult.CONTINUE;
            }
            files.add(new ScannedFile(relative(file), language.orElse(null), material, attrs.size()));
            language.ifPresent(l -> nearestModule(file).addFile(l));
            return FileVisitResult.CONTINUE;
        }

        @Override
        public FileVisitResult visitFileFailed(Path file, IOException exc) {
            LOG.debug("Fichier illisible ignoré : {}", file, exc);
            return FileVisitResult.CONTINUE;
        }

        private ModuleBuilder nearestModule(Path file) {
            Path current = file.getParent();
            while (current != null && current.startsWith(root)) {
                ModuleBuilder module = modules.get(current);
                if (module != null) {
                    return module;
                }
                current = current.getParent();
            }
            return modules.get(root);
        }

        private String relative(Path path) {
            String rel = root.relativize(path).toString().replace('\\', '/');
            return rel.isEmpty() ? ROOT_MODULE : rel;
        }
    }

    private static final class ModuleBuilder {
        private final String path;
        private final Set<Language> languages = EnumSet.noneOf(Language.class);
        private final List<String> manifests = new ArrayList<>();
        private boolean gitRepository;
        private int sourceFiles;

        ModuleBuilder(String path) {
            this.path = path;
        }

        void addFile(Language language) {
            if (language != Language.CONFIG) {
                languages.add(language);
                sourceFiles++;
            }
        }

        ProjectModule build() {
            return new ProjectModule(path, languages, manifests, gitRepository, sourceFiles);
        }
    }
}
