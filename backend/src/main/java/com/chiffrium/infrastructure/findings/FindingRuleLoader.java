package com.chiffrium.infrastructure.findings;

import com.chiffrium.domain.model.FindingCategory;
import com.chiffrium.domain.model.Language;
import com.chiffrium.domain.model.Severity;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

/**
 * Charge et valide les règles de constats embarquées ({@code resources/findings/}). Une règle invalide
 * empêche le démarrage : mieux vaut une erreur explicite qu'une détection silencieusement désactivée.
 */
public final class FindingRuleLoader {

    private static final String BASE = "/findings/";
    private static final String INDEX = "index.json";

    private final ObjectMapper mapper;

    public FindingRuleLoader(ObjectMapper mapper) {
        this.mapper = mapper;
    }

    /** Ensemble des règles et paramètres partagés. */
    public record FindingRuleSet(List<FindingRule> rules, CipherSuitePolicy cipherSuites,
                                 Map<Language, List<String>> commentPrefixes, Pattern testPath,
                                 Pattern placeholder, String suppressionMarker) {
    }

    record IndexDocument(int schemaVersion, List<String> files, String cipherSuites,
                         Map<String, List<String>> commentPrefixes, String testPathPattern,
                         String placeholderPattern, String suppressionMarker) {
    }

    record RulesDocument(List<RuleDocument> rules) {
    }

    record RuleDocument(String id, String category, String severity, String cwe, List<String> languages,
                        String pattern, String fileName, Boolean ignoreCase, String title, String description,
                        String recommendation, String secretGroup, Double minEntropy, String numberGroup, Long below,
                        String listGroup, String listCheck, List<String> required, String exclude,
                        String excludeFileName, Boolean includeComments, String traceGroup, String traceKind) {
    }

    record CipherSuitesDocument(List<WeaknessDocument> weaknesses) {
    }

    record WeaknessDocument(String pattern, String severity, String reason) {
    }

    public FindingRuleSet loadBuiltIn() {
        IndexDocument index = read(INDEX, IndexDocument.class);
        List<FindingRule> rules = new ArrayList<>();
        Set<String> ids = new HashSet<>();
        for (String file : index.files()) {
            for (RuleDocument doc : read(file, RulesDocument.class).rules()) {
                FindingRule rule = compile(file, doc);
                if (!ids.add(rule.id())) {
                    throw new IllegalStateException("Règle de constat en double : " + rule.id());
                }
                rules.add(rule);
            }
        }
        List<CipherSuitePolicy.Weakness> weaknesses = read(index.cipherSuites(), CipherSuitesDocument.class)
                .weaknesses().stream()
                .map(w -> new CipherSuitePolicy.Weakness(regex(index.cipherSuites(), w.pattern(), false),
                        Severity.fromId(w.severity()), Objects.requireNonNull(w.reason(), "reason")))
                .toList();
        Map<Language, List<String>> comments = new EnumMap<>(Language.class);
        index.commentPrefixes().forEach((id, prefixes) -> comments.put(language(INDEX, id), List.copyOf(prefixes)));
        return new FindingRuleSet(List.copyOf(rules), new CipherSuitePolicy(weaknesses), Map.copyOf(comments),
                regex(INDEX, index.testPathPattern(), false), regex(INDEX, index.placeholderPattern(), true),
                index.suppressionMarker());
    }

    static FindingRule compile(String file, RuleDocument doc) {
        String where = file + " / " + doc.id();
        require(doc.id() != null && !doc.id().isBlank(), where, "identifiant manquant");
        require((doc.pattern() == null) != (doc.fileName() == null), where, "exactement un de pattern / fileName");
        require(doc.title() != null && doc.recommendation() != null, where, "title et recommendation obligatoires");
        boolean ignoreCase = Boolean.TRUE.equals(doc.ignoreCase());
        Pattern pattern = doc.pattern() == null ? null : regex(where, doc.pattern(), ignoreCase);
        Pattern fileName = doc.fileName() == null ? null : regex(where, doc.fileName(), true);
        requireGroup(pattern, doc.secretGroup(), where);
        requireGroup(pattern, doc.numberGroup(), where);
        requireGroup(pattern, doc.listGroup(), where);
        require(doc.numberGroup() == null || doc.below() != null, where, "numberGroup et below vont ensemble");
        require(doc.below() == null || doc.numberGroup() != null || doc.traceGroup() != null, where,
                "below sans numberGroup ni traceGroup");
        FindingRule.ListCheck listCheck = doc.listCheck() == null ? null
                : FindingRule.ListCheck.valueOf(doc.listCheck().toUpperCase(Locale.ROOT).replace('-', '_'));
        require((doc.listGroup() == null) == (listCheck == null), where, "listGroup et listCheck vont ensemble");
        require(listCheck != FindingRule.ListCheck.REQUIRE_ALL || doc.required() != null && !doc.required().isEmpty(),
                where, "required obligatoire pour require-all");
        requireGroup(pattern, doc.traceGroup(), where);
        FindingRule.TraceKind traceKind = doc.traceKind() == null ? null
                : FindingRule.TraceKind.valueOf(doc.traceKind().toUpperCase(Locale.ROOT));
        require((doc.traceGroup() == null) == (traceKind == null), where, "traceGroup et traceKind vont ensemble");
        require(traceKind != FindingRule.TraceKind.NUMBER || doc.below() != null, where,
                "below obligatoire pour une trace de nombre");
        Set<Language> languages = new HashSet<>();
        if (doc.languages() != null) {
            doc.languages().forEach(id -> languages.add(language(where, id)));
        }
        try {
            return new FindingRule(doc.id(), FindingCategory.fromId(doc.category()), Severity.fromId(doc.severity()),
                    doc.cwe(), languages, pattern, fileName, doc.title(), doc.description(), doc.recommendation(),
                    doc.secretGroup(), doc.minEntropy() == null ? 0 : doc.minEntropy(), doc.numberGroup(), doc.below(),
                    doc.listGroup(), listCheck, doc.required(), doc.exclude() == null ? null : regex(where, doc.exclude(), true),
                    doc.excludeFileName() == null ? null : regex(where, doc.excludeFileName(), true),
                    Boolean.TRUE.equals(doc.includeComments()), doc.traceGroup(), traceKind);
        } catch (IllegalArgumentException e) {
            throw new IllegalStateException("Règle de constat invalide (" + where + ") : " + e.getMessage(), e);
        }
    }

    private static Language language(String where, String id) {
        return Language.fromId(id)
                .orElseThrow(() -> new IllegalStateException("Langage inconnu '" + id + "' (" + where + ")"));
    }

    private static void requireGroup(Pattern pattern, String group, String where) {
        if (group != null) {
            require(pattern != null && pattern.namedGroups().containsKey(group), where, "groupe absent : " + group);
        }
    }

    private static Pattern regex(String where, String value, boolean ignoreCase) {
        try {
            return Pattern.compile(Objects.requireNonNull(value, "motif manquant"),
                    ignoreCase ? Pattern.CASE_INSENSITIVE : 0);
        } catch (PatternSyntaxException e) {
            throw new IllegalStateException("Expression invalide (" + where + ") : " + e.getMessage(), e);
        }
    }

    private static void require(boolean condition, String where, String message) {
        if (!condition) {
            throw new IllegalStateException("Règle de constat invalide (" + where + ") : " + message);
        }
    }

    private <T> T read(String name, Class<T> type) {
        try (InputStream in = FindingRuleLoader.class.getResourceAsStream(BASE + name)) {
            if (in == null) {
                throw new IllegalStateException("Ressource absente : " + BASE + name);
            }
            return mapper.readValue(in, type);
        } catch (IOException e) {
            throw new UncheckedIOException("Lecture impossible : " + BASE + name, e);
        }
    }
}
