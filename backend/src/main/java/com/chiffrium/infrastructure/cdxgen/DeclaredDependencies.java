package com.chiffrium.infrastructure.cdxgen;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.function.Predicate;
import java.util.stream.Stream;

/**
 * Dépendances déclarées (pom.xml, fichiers Gradle, projets .NET, modules Go) lues sans lancer d'outil de
 * build, et BOM CycloneDX minimal qui les porte jusqu'au lecteur de dépendances.
 */
final class DeclaredDependencies {

    /** Dossiers de sortie ou de dépendances, jamais des sources du projet. */
    private static final Set<String> SKIPPED_DIRS = Set.of(".git", "target", "build", "node_modules", ".gradle", ".idea");
    private static final int MAX_DEPTH = 30;
    private static final int MAX_FILES = 2000;
    private static final long MAX_FILE_BYTES = 5L * 1024 * 1024;

    private DeclaredDependencies() {
    }

    /**
     * Dépendance déclarée. {@code ecosystem} est le type de purl (maven, nuget, golang) ; {@code groupId} est
     * l'espace de noms, vide pour NuGet ; {@code optional} marque ce qui ne sert pas à l'exécution (portée
     * test ou provided, module présent dans le graphe de build mais pas retenu).
     */
    record Dependency(String ecosystem, String groupId, String artifactId, String version, boolean optional) {

        /** Dépendance Maven : de loin le cas le plus courant, d'où ce raccourci. */
        Dependency(String groupId, String artifactId, String version, boolean optional) {
            this("maven", groupId, artifactId, version, optional);
        }

        String purl() {
            String namespace = groupId == null || groupId.isBlank() ? "" : groupId + "/";
            return "pkg:" + ecosystem + "/" + namespace + artifactId + (version != null ? "@" + version : "");
        }
    }

    /** Ajoute une dépendance ; une déclaration d'exécution l'emporte sur une déclaration de test. */
    static void add(Map<String, Dependency> into, Dependency dependency) {
        into.merge(dependency.purl(), dependency, (a, b) -> a.optional() && !b.optional() ? b : a);
    }

    /** Fichiers du projet (hors dossiers de sortie) dont le nom est accepté, taille et nombre bornés. */
    static List<Path> files(Path root, Predicate<String> name) throws IOException {
        try (Stream<Path> paths = Files.walk(root, MAX_DEPTH)) {
            return paths.filter(p -> p.getFileName() != null && name.test(p.getFileName().toString()))
                    .filter(p -> outsideSkippedDirs(root.relativize(p)))
                    .filter(DeclaredDependencies::smallRegularFile)
                    .limit(MAX_FILES)
                    .toList();
        }
    }

    private static boolean outsideSkippedDirs(Path relative) {
        for (Path part : relative) {
            if (SKIPPED_DIRS.contains(part.toString())) {
                return false;
            }
        }
        return true;
    }

    private static boolean smallRegularFile(Path file) {
        try {
            return Files.isRegularFile(file) && Files.size(file) <= MAX_FILE_BYTES;
        } catch (IOException e) {
            return false;
        }
    }

    /** Dépendances déclarées par le projet, tous écosystèmes confondus. */
    static Map<String, Dependency> read(Path projectRoot) throws IOException {
        Map<String, Dependency> all = new LinkedHashMap<>();
        Map<String, Dependency> maven = PomDependencyReader.read(projectRoot);
        maven.values().forEach(d -> add(all, d));
        GradleDependencyReader.read(projectRoot).values().forEach(d -> add(all, d));
        NugetDependencyReader.read(projectRoot).values().forEach(d -> add(all, d));
        GoDependencyReader.read(projectRoot).values().forEach(d -> add(all, d));
        // Les manifestes ne donnent que le premier niveau : le cache Maven local complète l'arbre s'il existe,
        // sans rien lancer ni télécharger.
        PomDependencyReader.transitive(maven, localMavenRepository()).values().forEach(d -> add(all, d));
        return all;
    }

    /** Cache Maven local, déplaçable par {@code -Dmaven.repo.local} ou {@code MAVEN_REPO_LOCAL}. */
    static Path localMavenRepository() {
        String configured = System.getProperty("maven.repo.local", System.getenv("MAVEN_REPO_LOCAL"));
        if (configured != null && !configured.isBlank()) {
            return Path.of(configured);
        }
        return Path.of(System.getProperty("user.home", ".")).resolve(".m2").resolve("repository");
    }

    /**
     * Écrit un BOM CycloneDX minimal des dépendances.
     * @return le fichier écrit, ou vide s'il n'y a aucune dépendance
     */
    static Optional<Path> writeBom(Map<String, Dependency> dependencies, Path output) throws IOException {
        if (dependencies.isEmpty()) {
            return Optional.empty();
        }
        ObjectMapper mapper = new ObjectMapper();
        ObjectNode bom = mapper.createObjectNode()
                .put("bomFormat", "CycloneDX").put("specVersion", "1.6").put("version", 1);
        ArrayNode components = bom.putArray("components");
        for (Dependency dependency : dependencies.values()) {
            ObjectNode component = components.addObject()
                    .put("type", "library")
                    .put("bom-ref", dependency.purl())
                    .put("name", dependency.artifactId())
                    .put("purl", dependency.purl())
                    .put("scope", dependency.optional() ? "optional" : "required");
            if (dependency.groupId() != null && !dependency.groupId().isBlank()) {
                component.put("group", dependency.groupId());
            }
            if (dependency.version() != null) {
                component.put("version", dependency.version());
            }
        }
        mapper.writerWithDefaultPrettyPrinter().writeValue(output.toFile(), bom);
        return Optional.of(output);
    }
}
