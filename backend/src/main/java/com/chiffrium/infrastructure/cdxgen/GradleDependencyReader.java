package com.chiffrium.infrastructure.cdxgen;

import com.chiffrium.infrastructure.cdxgen.DeclaredDependencies.Dependency;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Dépendances d'un projet Gradle lues sans lancer Gradle.
 *
 * <p>Les scripts build.gradle(.kts) sont du code (Groovy, Kotlin) : les exécuter, comme le fait cdxgen via le
 * gradlew du dépôt, revient à exécuter le dépôt analysé. On lit à la place, par ordre de fiabilité :
 * <ul>
 *   <li>les verrous {@code gradle.lockfile} : versions exactes, dépendances transitives comprises ;</li>
 *   <li>le catalogue de versions {@code gradle/*.versions.toml} (entrées utilisées par les scripts) ;</li>
 *   <li>les déclarations littérales des scripts ({@code implementation "g:a:v"}, notation
 *       {@code group: ..., name: ..., version: ...}), avec les variables de {@code gradle.properties} et les
 *       affectations simples ({@code def}, {@code val}, {@code ext}).</li>
 * </ul>
 * Une dépendance calculée par du code (boucle, fonction) n'est pas vue : c'est la limite de la lecture statique.
 */
final class GradleDependencyReader {

    private static final Pattern CONFIGURATION = Pattern.compile(
            "\\b(implementation|api|compileOnly|compileOnlyApi|runtimeOnly|compile|runtime|testCompile|testRuntime"
                    + "|annotationProcessor|kapt|ksp|classpath|provided|shadow|[a-z][A-Za-z0-9]*(?:Implementation|Api"
                    + "|CompileOnly|RuntimeOnly))\\b");
    private static final String PLATFORM = "(?:(?:enforcedPlatform|platform|testFixtures)\\s*\\(\\s*)?";
    private static final Pattern LITERAL = Pattern.compile(CONFIGURATION.pattern() + "\\s*\\(?\\s*" + PLATFORM
            + "[\"']([^\"'\\s:]+):([^\"'\\s:]+)(?::([^\"'\\s:@]+))?[^\"']*[\"']");
    private static final Pattern MAP_NOTATION = Pattern.compile(CONFIGURATION.pattern()
            + "\\s*\\(?\\s*group\\s*[:=]\\s*[\"']([^\"']+)[\"']\\s*,\\s*name\\s*[:=]\\s*[\"']([^\"']+)[\"']"
            + "(?:\\s*,\\s*version\\s*[:=]\\s*[\"']([^\"']+)[\"'])?");
    private static final Pattern CATALOG_REFERENCE = Pattern.compile(CONFIGURATION.pattern() + "\\s*\\(?\\s*"
            + PLATFORM + "libs\\.([A-Za-z0-9_.]+)");
    /** def x = '...', val x = "...", ext.x = '...', x = '...' dans un bloc ext, extra["x"] = "...". */
    private static final Pattern ASSIGNMENT = Pattern.compile(
            "(?m)^\\s*(?:def\\s+|val\\s+|var\\s+|ext\\.|project\\.ext\\.|extra\\[\\s*\"|set\\(\\s*\")?"
                    + "([A-Za-z_][A-Za-z0-9_.]*)\"?\\s*\\]?\\s*(?:=|,)\\s*[\"']([^\"'$]+)[\"']");
    private static final Pattern VARIABLE = Pattern.compile("\\$\\{?([A-Za-z_][A-Za-z0-9_.]*)}?");
    private static final Pattern TOML_SECTION = Pattern.compile("^\\s*\\[([A-Za-z0-9_.-]+)]\\s*$");
    private static final Pattern TOML_ENTRY = Pattern.compile("^\\s*([A-Za-z0-9_.\"-]+)\\s*=\\s*(.+?)\\s*$");
    private static final Pattern TOML_FIELD = Pattern.compile("([A-Za-z.]+)\\s*=\\s*\"([^\"]*)\"");
    private static final Pattern TOML_STRING = Pattern.compile("\"([^\"]*)\"");

    private GradleDependencyReader() {
    }

    static Map<String, Dependency> read(Path projectRoot) throws IOException {
        Map<String, Dependency> result = new LinkedHashMap<>();
        // buildscript-gradle.lockfile : plugins du build, pas des dépendances du projet.
        for (Path lockfile : DeclaredDependencies.files(projectRoot,
                n -> n.endsWith(".lockfile") && !n.equals("buildscript-gradle.lockfile"))) {
            readLockfile(lockfile, result);
        }
        List<Path> scripts = DeclaredDependencies.files(projectRoot,
                n -> n.equals("build.gradle") || n.equals("build.gradle.kts"));
        Map<String, String> variables = new HashMap<>();
        for (Path properties : DeclaredDependencies.files(projectRoot, "gradle.properties"::equals)) {
            readProperties(properties, variables);
        }
        List<String> texts = new ArrayList<>();
        for (Path script : scripts) {
            String text = Files.readString(script, StandardCharsets.UTF_8);
            texts.add(text);
            Matcher assignment = ASSIGNMENT.matcher(text);
            while (assignment.find()) {
                variables.putIfAbsent(assignment.group(1), assignment.group(2));
            }
        }
        Map<String, Boolean> catalogUses = new HashMap<>();
        for (String text : texts) {
            readLiterals(text, variables, result);
            Matcher reference = CATALOG_REFERENCE.matcher(text);
            while (reference.find()) {
                catalogUses.merge(accessor(reference.group(2)), testOnly(reference.group(1)), Boolean::logicalAnd);
            }
        }
        for (Path catalog : DeclaredDependencies.files(projectRoot, n -> n.endsWith(".versions.toml"))) {
            readCatalog(catalog, catalogUses, result);
        }
        return result;
    }

    private static void readLockfile(Path lockfile, Map<String, Dependency> into) throws IOException {
        for (String line : Files.readAllLines(lockfile, StandardCharsets.UTF_8)) {
            String entry = line.strip();
            int equals = entry.indexOf('=');
            if (entry.isEmpty() || entry.startsWith("#") || equals < 0 || entry.startsWith("empty=")) {
                continue;
            }
            String[] coordinates = entry.substring(0, equals).split(":");
            if (coordinates.length < 3) {
                continue;
            }
            boolean testOnly = true;
            for (String configuration : entry.substring(equals + 1).split(",")) {
                testOnly &= testOnly(configuration.strip());
            }
            DeclaredDependencies.add(into, new Dependency(coordinates[0], coordinates[1], coordinates[2], testOnly));
        }
    }

    private static void readProperties(Path file, Map<String, String> into) throws IOException {
        for (String line : Files.readAllLines(file, StandardCharsets.ISO_8859_1)) {
            String entry = line.strip();
            int separator = entry.indexOf('=');
            if (!entry.startsWith("#") && separator > 0) {
                into.putIfAbsent(entry.substring(0, separator).strip(), entry.substring(separator + 1).strip());
            }
        }
    }

    private static void readLiterals(String text, Map<String, String> variables, Map<String, Dependency> into) {
        for (Pattern pattern : List.of(LITERAL, MAP_NOTATION)) {
            Matcher matcher = pattern.matcher(text);
            while (matcher.find()) {
                String group = substitute(matcher.group(2), variables);
                String name = substitute(matcher.group(3), variables);
                if (group == null || name == null) {
                    continue;
                }
                DeclaredDependencies.add(into, new Dependency(group, name, substitute(matcher.group(4), variables),
                        testOnly(matcher.group(1))));
            }
        }
    }

    /** Remplace $x et ${x} connus ; renvoie null si une variable reste inconnue. */
    static String substitute(String value, Map<String, String> variables) {
        if (value == null) {
            return null;
        }
        Matcher matcher = VARIABLE.matcher(value);
        StringBuilder resolved = new StringBuilder();
        while (matcher.find()) {
            String replacement = variables.get(matcher.group(1));
            if (replacement == null && matcher.group(1).startsWith("project.")) {
                replacement = variables.get(matcher.group(1).substring("project.".length()));
            }
            if (replacement == null) {
                return null;
            }
            matcher.appendReplacement(resolved, Matcher.quoteReplacement(replacement));
        }
        matcher.appendTail(resolved);
        String result = resolved.toString().strip();
        return result.isEmpty() ? null : result;
    }

    /**
     * Catalogue de versions. Si les scripts utilisent le catalogue, seules les entrées référencées sont gardées
     * (un catalogue partagé déclare souvent plus de bibliothèques qu'un projet n'en utilise).
     */
    private static void readCatalog(Path catalog, Map<String, Boolean> uses, Map<String, Dependency> into)
            throws IOException {
        Map<String, String> versions = new HashMap<>();
        Map<String, String> libraries = new LinkedHashMap<>();
        Map<String, List<String>> bundles = new HashMap<>();
        String section = "";
        for (String line : Files.readAllLines(catalog, StandardCharsets.UTF_8)) {
            String content = line.replaceFirst("\\s+#.*$", "");
            Matcher header = TOML_SECTION.matcher(content);
            if (header.matches()) {
                section = header.group(1);
                continue;
            }
            Matcher entry = TOML_ENTRY.matcher(content);
            if (!entry.matches()) {
                continue;
            }
            String key = entry.group(1).replace("\"", "");
            String value = entry.group(2);
            switch (section) {
                case "versions" -> {
                    Matcher string = TOML_STRING.matcher(value);
                    if (string.find()) {
                        versions.put(key, string.group(1));
                    }
                }
                case "libraries" -> libraries.put(key, value);
                case "bundles" -> {
                    List<String> members = new ArrayList<>();
                    TOML_STRING.matcher(value).results().forEach(m -> members.add(m.group(1)));
                    bundles.put(accessor("bundles." + key), members);
                }
                default -> { }
            }
        }
        Map<String, Boolean> used = new HashMap<>();
        uses.forEach((reference, testOnly) -> {
            List<String> members = bundles.get(reference);
            if (members != null) {
                members.forEach(m -> used.merge(accessor(m), testOnly, Boolean::logicalAnd));
            } else {
                used.merge(reference, testOnly, Boolean::logicalAnd);
            }
        });
        Set<String> seen = new HashSet<>();
        libraries.forEach((alias, value) -> {
            String reference = accessor(alias);
            if ((!uses.isEmpty() && !used.containsKey(reference)) || !seen.add(reference)) {
                return;
            }
            Dependency dependency = catalogEntry(value, versions, !uses.isEmpty() && used.get(reference));
            if (dependency != null) {
                DeclaredDependencies.add(into, dependency);
            }
        });
    }

    private static Dependency catalogEntry(String value, Map<String, String> versions, boolean testOnly) {
        String group;
        String name;
        String version;
        if (value.startsWith("\"")) {
            String[] parts = value.replace("\"", "").strip().split(":");
            if (parts.length < 2) {
                return null;
            }
            group = parts[0];
            name = parts[1];
            version = parts.length > 2 ? parts[2] : null;
        } else {
            Map<String, String> fields = new HashMap<>();
            TOML_FIELD.matcher(value).results().forEach(m -> fields.putIfAbsent(m.group(1), m.group(2)));
            String module = fields.get("module");
            if (module != null && module.contains(":")) {
                group = module.substring(0, module.indexOf(':'));
                name = module.substring(module.indexOf(':') + 1);
            } else {
                group = fields.get("group");
                name = fields.get("name");
            }
            String reference = fields.getOrDefault("version.ref", fields.get("ref"));
            version = fields.get("version");
            if (version == null && reference != null) {
                version = versions.get(reference);
            }
            for (String constraint : List.of("strictly", "require", "prefer")) {
                version = version != null ? version : fields.get(constraint);
            }
        }
        return group == null || name == null ? null : new Dependency(group, name, version, testOnly);
    }

    /** Nom d'accès Gradle d'un alias de catalogue : "bc-prov" et "bc_prov" donnent libs.bc.prov. */
    private static String accessor(String alias) {
        return alias.toLowerCase(Locale.ROOT).replaceAll("[-_.]+", ".");
    }

    /** Configurations hors exécution : tests, compilation seule, processeurs d'annotations. */
    private static boolean testOnly(String configuration) {
        String lower = configuration.toLowerCase(Locale.ROOT);
        return lower.contains("test") || lower.startsWith("compileonly")
                || lower.equals("annotationprocessor") || lower.equals("kapt") || lower.equals("ksp")
                || lower.equals("classpath") || lower.equals("provided");
    }
}
