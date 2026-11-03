package com.chiffrium.infrastructure.cdxgen;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Repère les listes de dépendances calculées par du code (boucle Gradle, {@code install_requires} produit par
 * une fonction) : l'outil n'exécute jamais le code analysé, ces dépendances restent donc hors de l'inventaire.
 * Le rapport le dit, plutôt que de laisser croire à une liste complète.
 */
final class ComputedDependencies {

    static final int MAX_WARNINGS = 5;
    private static final Set<String> GRADLE_FILES = Set.of("build.gradle", "build.gradle.kts");
    private static final Pattern DEPENDENCIES_BLOCK = Pattern.compile("(?m)^\\s*dependencies\\s*\\{");
    /** Boucle ou jars locaux dans un bloc dependencies. */
    private static final Pattern GRADLE_COMPUTED = Pattern.compile(
            "\\.each\\s*\\{|\\.forEach\\s*[({]|\\bfor\\s*\\(|\\bfileTree\\s*\\(|\\bfiles\\s*\\(");
    /** install_requires qui n'est pas une liste écrite telle quelle. */
    private static final Pattern SETUP_COMPUTED = Pattern.compile("\\binstall_requires\\s*=\\s*(?!\\[)\\S");

    private ComputedDependencies() {
    }

    /** Un avertissement par fichier concerné (au plus {@link #MAX_WARNINGS}, puis un décompte). */
    static List<String> warnings(Path projectRoot) throws IOException {
        List<String> found = new ArrayList<>();
        for (Path file : DeclaredDependencies.files(projectRoot,
                name -> GRADLE_FILES.contains(name) || name.equals("setup.py"))) {
            String content = Files.readString(file, StandardCharsets.UTF_8);
            Integer line = file.getFileName().toString().equals("setup.py")
                    ? firstLine(content, SETUP_COMPUTED.matcher(content), 0, content.length())
                    : computedInDependencies(content);
            if (line != null) {
                found.add(projectRoot.relativize(file).toString().replace('\\', '/') + " (ligne " + line + ")");
            }
        }
        if (found.isEmpty()) {
            return List.of();
        }
        List<String> warnings = new ArrayList<>();
        for (String place : found.subList(0, Math.min(MAX_WARNINGS, found.size()))) {
            warnings.add("Dépendances peut-être incomplètes : " + place + " construit sa liste par du code, qui "
                    + "n'est pas exécuté ; les dépendances ainsi ajoutées ne sont pas inventoriées.");
        }
        if (found.size() > MAX_WARNINGS) {
            warnings.add("Dépendances peut-être incomplètes dans " + (found.size() - MAX_WARNINGS)
                    + " autre(s) fichier(s) de build.");
        }
        return warnings;
    }

    private static Integer computedInDependencies(String content) {
        Matcher block = DEPENDENCIES_BLOCK.matcher(content);
        while (block.find()) {
            int end = closingBrace(content, block.end() - 1);
            Integer line = firstLine(content, GRADLE_COMPUTED.matcher(content), block.end(), end);
            if (line != null) {
                return line;
            }
        }
        return null;
    }

    private static Integer firstLine(String content, Matcher matcher, int from, int to) {
        matcher.region(from, to);
        if (!matcher.find()) {
            return null;
        }
        return (int) content.substring(0, matcher.start()).chars().filter(c -> c == '\n').count() + 1;
    }

    private static int closingBrace(String content, int open) {
        int depth = 0;
        for (int i = open; i < content.length(); i++) {
            char c = content.charAt(i);
            if (c == '{') {
                depth++;
            } else if (c == '}' && --depth == 0) {
                return i;
            }
        }
        return content.length();
    }
}
