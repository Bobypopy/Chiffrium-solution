package com.chiffrium.infrastructure.rules;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Supplier;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Résout statiquement la valeur d'un argument : littéral, constante (même fichier puis ensemble du projet),
 * concaténation simple ({@code ALGO + "/CBC/PKCS5Padding"}) et valeur par défaut d'une lecture de configuration
 * ({@code props.getOrDefault("keyFile", "private.pem")}). Sans analyse de flux, les valeurs calculées à
 * l'exécution restent inconnues : c'est une limite assumée et signalée (actif "non résolu").
 */
final class ConstantResolver {

    private static final int MAX_VALUE_LENGTH = 200;
    private static final Pattern CONCATENATION_SPLIT = Pattern.compile("\\+(?=(?:[^\"'`]*[\"'`][^\"'`]*[\"'`])*[^\"'`]*$)");
    private static final Pattern QUOTED = Pattern.compile("^[bBrRuUfF@]{0,2}([\"'`])(.*)\\1$", Pattern.DOTALL);
    /** Définition "NOM = "valeur"" (Java, Kotlin, JS, Python, Go :=, C#, PHP $nom, Ruby, Rust const). */
    private static final String ASSIGNMENT_TEMPLATE =
            "(?<![\\w$])%s\\s*(?::\\s*[\\w<>\\[\\], .&']+)?\\s*(?::=|=|=>)\\s*[bBrRuUfF@]{0,2}([\"'`])([^\"'`\\n]{1,200})\\1";
    /** #define NOM "valeur" (C/C++). */
    private static final String DEFINE_TEMPLATE = "#define\\s+%s\\s+\"([^\"\\n]{1,200})\"";
    /** NOM = config.getOrDefault("clé", "défaut") et variantes getProperty / get / getenv. */
    private static final String DEFAULT_VALUE_TEMPLATE =
            "(?<![\\w$])%s\\s*=\\s*[\\w.()\\[\\]]*?\\.(?:getOrDefault|getProperty|get|getenv|getString)\\s*\\(\\s*[\"']([^\"']*)[\"']\\s*,\\s*[\"']([^\"'\\n]{1,200})[\"']";
    /** NOM = config.getProperty("clé") : résolu seulement si un fichier de réglages du projet définit la clé. */
    private static final String SETTING_TEMPLATE =
            "(?<![\\w$])%s\\s*=\\s*[\\w.()\\[\\]]*?\\.(?:getProperty|get|getenv|getString)\\s*\\(\\s*[\"']([^\"'\\n]{1,200})[\"']\\s*\\)";
    /** NOM = 2048 (Java, Kotlin, C#, Go :=, Python...), avec un type éventuel. */
    private static final String NUMBER_TEMPLATE =
            "(?<![\\w$.])%s\\s*(?::\\s*[\\w<>?]+)?\\s*(?::=|=)\\s*(\\d{2,5})(?![\\w.])";
    private static final Pattern GLOBAL_ASSIGNMENT = Pattern.compile(
            "(?<![\\w$])([A-Za-z_$][\\w$]*)\\s*(?::\\s*[\\w<>\\[\\], .&']+)?\\s*(?::=|=)\\s*[bBrRuUfF@]{0,2}([\"'`])([^\"'`\\n]{1,200})\\2");

    private final Supplier<Map<String, List<String>>> projectIndex;
    private final Supplier<Map<String, List<String>>> settings;
    private final Map<String, Pattern> patternCache = new HashMap<>();

    /**
     * @param projectIndex fournit (paresseusement) les définitions de constantes de tout le projet
     */
    ConstantResolver(Supplier<Map<String, List<String>>> projectIndex) {
        this(projectIndex, Map::of);
    }

    /**
     * @param settings réglages du projet (.properties, YAML...) : la valeur d'une clé lue par getProperty
     */
    ConstantResolver(Supplier<Map<String, List<String>>> projectIndex, Supplier<Map<String, List<String>>> settings) {
        this.projectIndex = projectIndex;
        this.settings = settings;
    }

    /**
     * @return la valeur résolue, ou vide si une partie de l'expression est inconnue
     */
    Optional<String> resolve(String expression, String fileContent) {
        if (expression == null || expression.isBlank()) {
            return Optional.empty();
        }
        StringBuilder value = new StringBuilder();
        for (String part : CONCATENATION_SPLIT.split(expression)) {
            Optional<String> resolved = resolveAtom(part.trim(), fileContent);
            if (resolved.isEmpty()) {
                return Optional.empty();
            }
            value.append(resolved.get());
        }
        return value.length() > MAX_VALUE_LENGTH ? Optional.empty() : Optional.of(value.toString());
    }

    /**
     * Taille passée par une variable ou une constante numérique du fichier ({@code int keysize = 1024;}) ;
     * vide si elle n'est jamais affectée d'un nombre, ou l'est de plusieurs valeurs différentes.
     */
    Optional<Integer> resolveNumber(String identifier, String fileContent) {
        String name = lastSegment(identifier.trim());
        if (name.isEmpty() || !Character.isJavaIdentifierStart(name.charAt(0))) {
            return Optional.empty();
        }
        Pattern pattern = patternCache.computeIfAbsent(NUMBER_TEMPLATE + name,
                k -> Pattern.compile(String.format(NUMBER_TEMPLATE, Pattern.quote(name))));
        Matcher matcher = pattern.matcher(fileContent);
        Integer value = null;
        while (matcher.find()) {
            int found = Integer.parseInt(matcher.group(1));
            if (value != null && value != found) {
                return Optional.empty();
            }
            value = found;
        }
        return Optional.ofNullable(value);
    }

    static boolean isLiteral(String expression) {
        return expression != null && QUOTED.matcher(expression.trim()).matches();
    }

    /** Dernier segment d'un identifiant qualifié : "this.algo" -> "algo", "Cipher::AES" -> "AES". */
    static String lastSegment(String identifier) {
        String[] parts = identifier.split("\\.|::");
        return parts.length == 0 ? identifier : parts[parts.length - 1];
    }

    private Optional<String> resolveAtom(String atom, String fileContent) {
        Matcher quoted = QUOTED.matcher(atom);
        if (quoted.matches()) {
            String literal = quoted.group(2);
            return literal.contains("${") ? Optional.empty() : Optional.of(literal);
        }
        String identifier = lastSegment(atom);
        if (identifier.isEmpty() || !Character.isJavaIdentifierStart(identifier.charAt(0))) {
            return Optional.empty();
        }
        return findInFile(identifier, fileContent).or(() -> findInProject(identifier));
    }

    private Optional<String> findInFile(String identifier, String content) {
        for (String template : List.of(ASSIGNMENT_TEMPLATE, DEFINE_TEMPLATE, DEFAULT_VALUE_TEMPLATE, SETTING_TEMPLATE)) {
            Pattern pattern = patternCache.computeIfAbsent(template + identifier,
                    k -> Pattern.compile(String.format(template, Pattern.quote(identifier))));
            Matcher matcher = pattern.matcher(content);
            while (matcher.find()) {
                if (StringLiterals.inside(content, matcher.start(), true)) {
                    continue;
                }
                if (template.equals(DEFAULT_VALUE_TEMPLATE)) {
                    // La valeur du fichier de réglages l'emporte sur la valeur de repli écrite dans le code.
                    return Optional.of(setting(matcher.group(1)).orElse(matcher.group(2)));
                }
                if (template.equals(SETTING_TEMPLATE)) {
                    Optional<String> configured = setting(matcher.group(1));
                    if (configured.isPresent()) {
                        return configured;
                    }
                    continue;
                }
                return Optional.of(matcher.group(matcher.groupCount()));
            }
        }
        return Optional.empty();
    }

    /** Valeur d'une clé de réglage, si un seul fichier la définit (ou tous de la même façon). */
    private Optional<String> setting(String key) {
        List<String> values = settings.get().getOrDefault(key, List.of());
        return values.size() == 1 ? Optional.of(values.get(0)) : Optional.empty();
    }

    /** Une constante définie plusieurs fois avec des valeurs différentes est ambiguë : non résolue. */
    private Optional<String> findInProject(String identifier) {
        List<String> values = projectIndex.get().getOrDefault(identifier, List.of());
        return values.size() == 1 ? Optional.of(values.get(0)) : Optional.empty();
    }

    /** Construit l'index "constante -> valeurs distinctes" d'un ensemble de contenus. */
    static Map<String, List<String>> buildIndex(Iterable<String> contents) {
        Map<String, List<String>> index = new HashMap<>();
        for (String content : contents) {
            indexInto(index, content);
        }
        return index;
    }

    /** Ajoute à l'index les constantes d'un contenu (lecture fichier par fichier, sans tout garder en mémoire). */
    static void indexInto(Map<String, List<String>> index, String content) {
        Matcher matcher = GLOBAL_ASSIGNMENT.matcher(content);
        while (matcher.find()) {
            // "Rsa{algorithmId=" + algorithmId + "}" : du texte affiché, pas une constante.
            if (StringLiterals.inside(content, matcher.start(), true)) {
                continue;
            }
            List<String> values = index.computeIfAbsent(matcher.group(1), k -> new ArrayList<>());
            if (!values.contains(matcher.group(3))) {
                values.add(matcher.group(3));
            }
        }
    }
}
