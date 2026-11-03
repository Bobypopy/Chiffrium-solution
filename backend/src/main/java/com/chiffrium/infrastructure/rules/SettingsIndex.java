package com.chiffrium.infrastructure.rules;

import com.chiffrium.application.port.ProjectScanner.ScannedFile;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Deque;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Réglages du projet ({@code hashAlg1=MD5} dans un .properties, {@code app.crypto.algorithm} dans un YAML) : la
 * valeur réellement employée par {@code props.getProperty("hashAlg1", "SHA512")}, plutôt que la valeur de repli.
 */
final class SettingsIndex {

    private static final Logger LOG = LoggerFactory.getLogger(SettingsIndex.class);
    private static final Set<String> FLAT = Set.of("properties", "env", "ini", "cfg");
    private static final Set<String> YAML = Set.of("yml", "yaml");
    /** clé=valeur, clé: valeur, clé valeur (.properties accepte les trois). */
    private static final Pattern FLAT_ENTRY = Pattern.compile("^\\s*(?:export\\s+)?([\\w.-]+)\\s*[=:]\\s*(.*?)\\s*$");
    private static final Pattern YAML_ENTRY = Pattern.compile("^( *)([\\w.-]+)\\s*:(?:\\s+(.*?))?\\s*$");
    private static final Pattern QUOTED = Pattern.compile("^([\"'])(.*)\\1$");
    private static final Pattern TRAILING_COMMENT = Pattern.compile("\\s+#.*$");

    private SettingsIndex() {
    }

    /** Clé -> valeurs distinctes : une clé définie différemment selon le fichier (profils) reste ambiguë. */
    static Map<String, List<String>> build(Path root, List<ScannedFile> files) {
        Map<String, List<String>> index = new HashMap<>();
        for (ScannedFile file : files) {
            String extension = extension(file.path());
            boolean yaml = YAML.contains(extension);
            if (!yaml && !FLAT.contains(extension)) {
                continue;
            }
            try {
                List<String> lines = Files.readAllLines(root.resolve(file.path()), StandardCharsets.UTF_8);
                if (yaml) {
                    readYaml(lines, index);
                } else {
                    readFlat(lines, index);
                }
            } catch (IOException | RuntimeException e) {
                LOG.debug("Fichier de réglages ignoré : {}", file.path(), e);
            }
        }
        return index;
    }

    private static void readFlat(List<String> lines, Map<String, List<String>> index) {
        for (String line : lines) {
            String trimmed = line.strip();
            if (trimmed.isEmpty() || "#!;[".indexOf(trimmed.charAt(0)) >= 0) {
                continue;
            }
            Matcher entry = FLAT_ENTRY.matcher(line);
            if (entry.matches()) {
                add(index, entry.group(1), entry.group(2));
            }
        }
    }

    /** YAML par indentation : app: / crypto: / algorithm: MD5 donne app.crypto.algorithm. */
    private static void readYaml(List<String> lines, Map<String, List<String>> index) {
        Deque<int[]> indents = new ArrayDeque<>();
        Deque<String> keys = new ArrayDeque<>();
        for (String line : lines) {
            if (line.isBlank() || line.strip().startsWith("#") || line.strip().startsWith("-")) {
                continue;
            }
            Matcher entry = YAML_ENTRY.matcher(line);
            if (!entry.matches()) {
                continue;
            }
            int indent = entry.group(1).length();
            while (!indents.isEmpty() && indents.peek()[0] >= indent) {
                indents.pop();
                keys.pop();
            }
            String value = entry.group(3);
            if (value == null || value.isEmpty()) {
                indents.push(new int[]{indent});
                keys.push(entry.group(2));
                continue;
            }
            List<String> path = new ArrayList<>(keys);
            Collections.reverse(path);
            path.add(entry.group(2));
            add(index, String.join(".", path), value);
        }
    }

    private static void add(Map<String, List<String>> index, String key, String raw) {
        String value = TRAILING_COMMENT.matcher(raw).replaceFirst("");
        Matcher quoted = QUOTED.matcher(value);
        if (quoted.matches()) {
            value = quoted.group(2);
        }
        if (value.isEmpty() || value.contains("${")) {
            return;
        }
        List<String> values = index.computeIfAbsent(key, k -> new ArrayList<>());
        if (!values.contains(value)) {
            values.add(value);
        }
    }

    private static String extension(String path) {
        String name = path.substring(path.lastIndexOf('/') + 1);
        int dot = name.lastIndexOf('.');
        return dot < 0 ? name.toLowerCase(Locale.ROOT) : name.substring(dot + 1).toLowerCase(Locale.ROOT);
    }
}
