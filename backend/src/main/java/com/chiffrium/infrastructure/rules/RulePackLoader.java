package com.chiffrium.infrastructure.rules;

import com.chiffrium.domain.model.CryptoFunction;
import com.chiffrium.domain.model.Language;
import com.chiffrium.domain.model.Primitive;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;
import java.util.stream.StreamSupport;

/**
 * Charge les paquets de règles JSON embarqués (src/main/resources/rules). La liste des fichiers est lue
 * dans rules/index.json car on ne peut pas lister de façon fiable un dossier à l'intérieur d'un JAR.
 *
 * <p>Raccourcis disponibles dans les expressions (évitent de dupliquer des motifs complexes) :
 * <ul>
 *   <li>{@code {ARG}} : argument (littéral, identifiant, concaténation) dans le groupe {@code algo} ;</li>
 *   <li>{@code {STR}} : littéral chaîne uniquement, groupe {@code algo} ;</li>
 *   <li>{@code {FILE}} : argument "chemin de fichier", groupe {@code file} ;</li>
 *   <li>{@code {SIZE}} : taille de clé (2 à 5 chiffres), groupe {@code size}.</li>
 * </ul>
 */
public final class RulePackLoader {

    private static final String INDEX = "/rules/index.json";
    private static final String RULES_DIR = "/rules/";
    /** "auto" : clé secrète pour une primitive symétrique, clé privée sinon (API qui génèrent les deux). */
    private static final Set<String> KEY_TYPES = Set.of("private-key", "secret-key", "auto");

    private static final String STRING_LITERAL =
            "(?:[bBrRuUfF@]{0,2}\"[^\"\\n]*\"|[bBrRuUfF]{0,2}'[^'\\n]*'|`[^`\\n]*`)";
    private static final String ARGUMENT_ATOM = "(?:" + STRING_LITERAL + "|[\\w$.:]+)";
    private static final String ARGUMENT = ARGUMENT_ATOM + "(?:\\s*\\+\\s*" + ARGUMENT_ATOM + ")*";
    private static final Map<String, String> PLACEHOLDERS = Map.of(
            "{ARG}", "(?<algo>" + ARGUMENT + ")",
            "{STR}", "(?<algo>" + STRING_LITERAL + ")",
            "{FILE}", "(?<file>" + ARGUMENT + ")",
            "{SIZE}", "(?<size>\\d{2,5})");

    private final ObjectMapper mapper;

    public RulePackLoader(ObjectMapper mapper) {
        this.mapper = mapper;
    }

    public List<RulePack> loadBuiltIn() {
        JsonNode index = read(INDEX);
        List<RulePack> packs = new ArrayList<>();
        Set<String> ruleIds = new HashSet<>();
        for (JsonNode file : index) {
            RulePack pack = parse(read(RULES_DIR + file.asText()), file.asText());
            for (Rule rule : pack.rules()) {
                if (!ruleIds.add(rule.id())) {
                    throw new IllegalStateException("Identifiant de règle dupliqué : " + rule.id());
                }
            }
            packs.add(pack);
        }
        return List.copyOf(packs);
    }

    RulePack parse(JsonNode node, String origin) {
        Set<Language> languages = EnumSet.noneOf(Language.class);
        for (JsonNode language : node.path("languages")) {
            languages.add(Language.fromId(language.asText())
                    .orElseThrow(() -> new IllegalStateException(origin + " : langage inconnu " + language)));
        }
        List<Rule> rules = new ArrayList<>();
        for (JsonNode rule : node.path("rules")) {
            rules.add(parseRule(rule, origin));
        }
        return new RulePack(
                text(node, "id", origin),
                languages,
                strings(node.path("commentPrefixes")),
                strings(node.path("functionPatterns")).stream().map(p -> compile(p, origin + " (fonctions)")).toList(),
                strings(node.path("classPatterns")).stream().map(p -> compile(p, origin + " (classes)")).toList(),
                node.path("blockStyle").asText("braces"),
                rules);
    }

    private Rule parseRule(JsonNode node, String origin) {
        String id = text(node, "id", origin);
        String where = origin + " / " + id;
        Rule.Kind kind = node.hasNonNull("kind")
                ? Rule.Kind.valueOf(node.get("kind").asText().toUpperCase(Locale.ROOT))
                : Rule.Kind.ALGORITHM;
        Pattern pattern = compile(text(node, "pattern", where), where);
        validateGroups(kind, pattern, node, where);

        Map<String, String> map = new LinkedHashMap<>();
        node.path("map").properties().forEach(e -> map.put(e.getKey().toLowerCase(Locale.ROOT), e.getValue().asText()));
        Map<String, List<CryptoFunction>> functionsByApi = new LinkedHashMap<>();
        node.path("functionsByApi").properties().forEach(e -> functionsByApi.put(e.getKey(), functions(e.getValue())));
        Map<String, Primitive> primitiveByApi = new LinkedHashMap<>();
        node.path("primitiveByApi").properties().forEach(e -> primitiveByApi.put(e.getKey(),
                Primitive.fromCycloneDx(e.getValue().asText())));
        String key = node.hasNonNull("key") ? keyType(node.get("key").asText(), where) : null;
        Map<String, String> keyByApi = new LinkedHashMap<>();
        node.path("keyByApi").properties().forEach(e -> keyByApi.put(e.getKey(), keyType(e.getValue().asText(), where)));

        return new Rule(id, kind, pattern,
                node.hasNonNull("algorithm") ? node.get("algorithm").asText() : null,
                node.hasNonNull("template") ? node.get("template").asText() : null,
                map,
                functions(node.path("functions")),
                functionsByApi,
                node.hasNonNull("primitive") ? Primitive.fromCycloneDx(node.get("primitive").asText()) : null,
                primitiveByApi,
                node.path("skipUnrecognized").asBoolean(false),
                node.hasNonNull("direction") ? node.get("direction").asText() : null,
                key,
                keyByApi);
    }

    private static String keyType(String value, String where) {
        if (!KEY_TYPES.contains(value)) {
            throw new IllegalStateException(where + " : type de clé inconnu " + value + " (attendu : " + KEY_TYPES + ")");
        }
        return value;
    }

    private static void validateGroups(Rule.Kind kind, Pattern pattern, JsonNode node, String where) {
        Set<String> groups = pattern.namedGroups().keySet();
        boolean ok = switch (kind) {
            case ALGORITHM -> node.hasNonNull("algorithm") || node.hasNonNull("template") || groups.contains("algo")
                    || groups.contains("name") || groups.contains("list");
            case KEYSIZE, KEYBYTES -> groups.contains("size");
            case MODE -> groups.contains("mode") || node.hasNonNull("algorithm");
            case PADDING -> groups.contains("padding") || node.hasNonNull("algorithm");
            case CURVE -> groups.contains("curve");
            case FILE -> groups.contains("file") && (node.hasNonNull("direction") || groups.contains("mode")
                    || groups.contains("op"));
        };
        if (!ok) {
            throw new IllegalStateException(where + " : groupes nommés manquants pour une règle " + kind);
        }
    }

    private static Pattern compile(String regex, String where) {
        String expanded = regex;
        for (Map.Entry<String, String> placeholder : PLACEHOLDERS.entrySet()) {
            expanded = expanded.replace(placeholder.getKey(), placeholder.getValue());
        }
        try {
            return Pattern.compile(expanded, Pattern.MULTILINE);
        } catch (PatternSyntaxException e) {
            throw new IllegalStateException(where + " : expression invalide : " + e.getMessage(), e);
        }
    }

    private static List<CryptoFunction> functions(JsonNode array) {
        return strings(array).stream().map(CryptoFunction::fromCycloneDx).toList();
    }

    private static List<String> strings(JsonNode array) {
        if (array == null || !array.isArray()) {
            return List.of();
        }
        return StreamSupport.stream(array.spliterator(), false).map(JsonNode::asText).toList();
    }

    private static String text(JsonNode node, String field, String where) {
        if (!node.hasNonNull(field) || node.get(field).asText().isBlank()) {
            throw new IllegalStateException(where + " : champ '" + field + "' obligatoire");
        }
        return node.get(field).asText();
    }

    private JsonNode read(String resource) {
        try (InputStream in = RulePackLoader.class.getResourceAsStream(resource)) {
            if (in == null) {
                throw new IllegalStateException("Ressource manquante : " + resource);
            }
            return mapper.readTree(in);
        } catch (IOException e) {
            throw new UncheckedIOException("Règles illisibles : " + resource, e);
        }
    }
}
