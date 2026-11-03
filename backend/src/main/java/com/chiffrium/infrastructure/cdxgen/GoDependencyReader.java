package com.chiffrium.infrastructure.cdxgen;

import com.chiffrium.infrastructure.cdxgen.DeclaredDependencies.Dependency;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Dépendances Go lues sans lancer la chaîne d'outils Go.
 *
 * <p>{@code go.mod} donne les modules retenus par la sélection de version minimale : ce sont ceux qui seront
 * réellement compilés. {@code go.sum} contient en plus les modules vus pendant la résolution mais pas
 * forcément retenus ; ils sont ajoutés en "optional" pour ne pas laisser croire qu'ils sont dans le binaire.
 * {@code vendor/modules.txt} sert quand le dépôt embarque ses dépendances.
 */
final class GoDependencyReader {

    private static final Logger LOG = LoggerFactory.getLogger(GoDependencyReader.class);
    /**
     * "module v1.2.3" éventuellement suivi de "// indirect". Pas de groupe répété dont les classes se
     * recouvrent : un go.mod piégé ne doit pas pouvoir faire exploser le temps de reconnaissance.
     */
    private static final Pattern REQUIREMENT = Pattern.compile(
            "^\\s*(?:require\\s+)?(?<module>[\\w.~-]+(?:/[\\w.~+-]+)+)\\s+"
                    + "(?<version>v[\\w.+-]+)\\s*(?<comment>//.*)?$");
    private static final Pattern SUM_LINE = Pattern.compile(
            "^(?<module>\\S+)\\s+(?<version>v[\\w.+-]+?)(?:/go\\.mod)?\\s+h1:\\S+$");
    private static final Pattern VENDORED = Pattern.compile("^#\\s+(?<module>\\S+)\\s+(?<version>v[\\w.+-]+)$");
    /** Un go.sum d'un gros dépôt peut faire des milliers de lignes ; au-delà, l'inventaire n'apprend plus rien. */
    private static final int MAX_LINES = 20_000;

    private GoDependencyReader() {
    }

    /** Modules Go du projet, dédoublonnés (clé : purl). */
    static Map<String, Dependency> read(Path projectRoot) throws IOException {
        Map<String, Dependency> result = new LinkedHashMap<>();
        for (Path file : DeclaredDependencies.files(projectRoot, "go.mod"::equals)) {
            readModuleFile(file, result);
        }
        for (Path file : DeclaredDependencies.files(projectRoot, "modules.txt"::equals)) {
            if (file.getParent() != null && "vendor".equals(String.valueOf(file.getParent().getFileName()))) {
                forEachLine(file, line -> add(result, VENDORED.matcher(line), false));
            }
        }
        for (Path file : DeclaredDependencies.files(projectRoot, "go.sum"::equals)) {
            // Retenu ou non, un module listé ici a été téléchargé : il mérite d'apparaître, en second rang.
            forEachLine(file, line -> add(result, SUM_LINE.matcher(line), true));
        }
        return result;
    }

    private static void readModuleFile(Path file, Map<String, Dependency> into) {
        boolean[] inRequireBlock = {false};
        forEachLine(file, line -> {
            String trimmed = line.strip();
            if (trimmed.startsWith("require (")) {
                inRequireBlock[0] = true;
                return;
            }
            if (inRequireBlock[0] && trimmed.startsWith(")")) {
                inRequireBlock[0] = false;
                return;
            }
            // Hors bloc, seules les lignes "require ..." comptent : "replace" et "exclude" ne sont pas
            // des dépendances du projet.
            if (!inRequireBlock[0] && !trimmed.startsWith("require ")) {
                return;
            }
            add(into, REQUIREMENT.matcher(trimmed), false);
        });
    }

    private static void add(Map<String, Dependency> into, Matcher matcher, boolean optional) {
        if (!matcher.matches()) {
            return;
        }
        String module = matcher.group("module");
        int lastSlash = module.lastIndexOf('/');
        String namespace = lastSlash > 0 ? module.substring(0, lastSlash) : null;
        String name = lastSlash > 0 ? module.substring(lastSlash + 1) : module;
        DeclaredDependencies.add(into,
                new Dependency("golang", namespace, name, matcher.group("version"), optional));
    }

    private static void forEachLine(Path file, java.util.function.Consumer<String> consumer) {
        try {
            List<String> lines = Files.readAllLines(file, StandardCharsets.UTF_8);
            lines.stream().limit(MAX_LINES).forEach(consumer);
        } catch (IOException | RuntimeException e) {
            LOG.debug("Fichier Go illisible, ignoré : {}", file, e);
        }
    }
}
