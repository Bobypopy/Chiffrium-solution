package com.chiffrium.infrastructure.findings;

import com.chiffrium.application.port.CryptoDetector;
import com.chiffrium.application.port.ProjectScanner.ScannedFile;
import com.chiffrium.domain.model.FindingCategory;
import com.chiffrium.domain.model.Language;
import com.chiffrium.domain.model.SecurityFinding;
import com.chiffrium.domain.model.Severity;
import com.chiffrium.infrastructure.findings.FindingRuleLoader.FindingRuleSet;
import com.chiffrium.infrastructure.rules.SourceText;
import com.chiffrium.infrastructure.scan.ArchiveEntries;
import com.chiffrium.infrastructure.scan.FileClassifier;
import com.chiffrium.infrastructure.scan.FileFailures;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * Détecteur de constats de sécurité : secrets en clair, validation TLS désactivée, aléa prévisible,
 * matériel cryptographique en dur, dérivation de clé faible, suites TLS obsolètes, configuration de
 * protocole risquée. Les règles sont des données ({@code resources/findings/}).
 *
 * <p>Réduction du bruit : valeurs factices et variables d'environnement ignorées, filtre d'entropie pour
 * les secrets génériques, gravité abaissée dans le code de test, suppression explicite par un commentaire
 * contenant le marqueur de suppression sur la ligne concernée.
 */
public final class SecurityFindingDetector implements CryptoDetector {

    /** Nombre de caractères du secret laissés visibles pour permettre de le retrouver. */
    static final int VISIBLE_SECRET_PREFIX = 4;
    private static final int ID_HEX_LENGTH = 16;
    /** Séparateur des listes de type "jdk.tls.disabledAlgorithms" (virgules, continuations de ligne). */
    private static final Pattern LIST_SEPARATOR = Pattern.compile("[,\\\\\\r\\n\"]+");
    private static final Set<FindingCategory> ALL_CATEGORIES = EnumSet.allOf(FindingCategory.class);
    /** Ce qui reste exploitable une fois supprimé du code : secrets, clés, IV et sels en dur. */
    private static final Set<FindingCategory> HISTORY_CATEGORIES = EnumSet.of(FindingCategory.SECRET,
            FindingCategory.HARDCODED_KEY_MATERIAL);

    private final FindingRuleSet ruleSet;

    public SecurityFindingDetector(FindingRuleSet ruleSet) {
        this.ruleSet = ruleSet;
    }

    @Override
    public String name() {
        return "sécurité";
    }

    @Override
    public DetectionResult detect(DetectionContext context) {
        Map<String, SecurityFinding> findings = new LinkedHashMap<>();
        List<String> warnings = new ArrayList<>();
        FileFailures failures = new FileFailures(name());
        for (ScannedFile file : context.scan().files()) {
            if (FileClassifier.isArchive(file.path())) {
                try {
                    ArchiveEntries.forEach(context.projectRoot().resolve(file.path()), entry -> {
                        String shown = file.path() + ArchiveEntries.SEPARATOR + entry.path();
                        if (FileClassifier.isScanned(fileName(shown))) {
                            contentFindings(shown, entry.content(), null, ALL_CATEGORIES).forEach(f -> add(findings, f));
                        }
                    });
                } catch (IOException | RuntimeException | StackOverflowError e) {
                    failures.record(file.path(), e);
                }
                continue;
            }
            Source source = source(file.path(), file.language(), null);
            fileFindings(source, ALL_CATEGORIES).forEach(f -> add(findings, f));
            if (file.material() && file.language() == null && !isTextMaterial(fileName(file.path()))) {
                continue;
            }
            Optional<SourceText> text;
            try {
                text = SourceText.load(context.projectRoot().resolve(file.path()));
            } catch (IOException e) {
                warnings.add("Lecture impossible : " + file.path());
                continue;
            }
            try {
                text.ifPresent(t -> analyze(source, t, ALL_CATEGORIES).forEach(f -> add(findings, f)));
            } catch (RuntimeException | StackOverflowError e) {
                failures.record(file.path(), e);
            }
        }
        warnings.addAll(failures.warnings());
        List<SecurityFinding> sorted = findings.values().stream()
                .sorted(SecurityFinding.BY_SEVERITY_THEN_LOCATION)
                .toList();
        return new DetectionResult(List.of(), List.of(), warnings, sorted);
    }

    /**
     * Constats de secrets et de clés d'une version de fichier tirée de l'historique Git. Les autres familles
     * (aléa, TLS, dérivation...) ne concernent que le code actuel.
     *
     * @param commit commit où cette version du fichier a été vue
     */
    public List<SecurityFinding> historyFindings(String path, byte[] content, String commit) {
        return contentFindings(path, content, commit, HISTORY_CATEGORIES);
    }

    /** Fichier lu ailleurs que sur le disque (version de l'historique, entrée d'archive). */
    private List<SecurityFinding> contentFindings(String path, byte[] content, String commit,
                                                  Set<FindingCategory> categories) {
        String name = fileName(path);
        Language language = FileClassifier.languageOf(name).orElse(null);
        Source source = source(path, language, commit);
        List<SecurityFinding> result = new ArrayList<>(fileFindings(source, categories));
        if (!FileClassifier.isMaterial(name) || language != null || isTextMaterial(name)) {
            SourceText.of(content).ifPresent(t -> result.addAll(analyze(source, t, categories)));
        }
        return result;
    }

    /** Fichier analysé : langage (UNKNOWN pour un fichier de données), code de test, commit s'il est ancien. */
    private record Source(String path, Language language, boolean testCode, String commit) {
    }

    private Source source(String path, Language language, String commit) {
        return new Source(path, language == null ? Language.UNKNOWN : language,
                ruleSet.testPath().matcher(path).find(), commit);
    }

    private List<SecurityFinding> fileFindings(Source source, Set<FindingCategory> categories) {
        String name = fileName(source.path());
        return ruleSet.rules().stream()
                .filter(rule -> categories.contains(rule.category()))
                .filter(rule -> rule.fileName() != null && rule.fileName().matcher(name).matches())
                .map(rule -> fileFinding(rule, source))
                .toList();
    }

    private List<SecurityFinding> analyze(Source source, SourceText text, Set<FindingCategory> categories) {
        Language language = source.language();
        List<String> comments = ruleSet.commentPrefixes().getOrDefault(language, List.of());
        List<SecurityFinding> result = new ArrayList<>();
        for (FindingRule rule : ruleSet.rules()) {
            if (rule.pattern() == null || !rule.appliesTo(language) || !categories.contains(rule.category())) {
                continue;
            }
            Matcher matcher = rule.pattern().matcher(text.content());
            while (matcher.find()) {
                int line = text.lineOf(matcher.start());
                String lineText = text.line(line);
                if (lineText.contains(ruleSet.suppressionMarker())
                        || !rule.includeComments() && text.isCommentLine(line, comments)
                        || rule.exclude() != null && rule.exclude().matcher(lineText).find()) {
                    continue;
                }
                evaluate(rule, matcher).ifPresent(match -> result.add(finding(rule, source, text, line,
                        text.columnOf(matcher.start()), match)));
            }
        }
        return result;
    }

    /**
     * Vérifications complémentaires d'une correspondance.
     *
     * @return l'élément déclencheur (caviardé si c'est un secret) et la gravité, ou vide si la correspondance
     * ne constitue pas un constat
     */
    private Optional<Match> evaluate(FindingRule rule, Matcher matcher) {
        Severity severity = rule.severity();
        String evidence = null;
        String detail = null;
        if (rule.secretGroup() != null) {
            String secret = matcher.group(rule.secretGroup());
            if (secret == null || ruleSet.placeholder().matcher(secret).find()
                    || rule.minEntropy() > 0 && Entropy.shannon(secret) < rule.minEntropy()) {
                return Optional.empty();
            }
            evidence = redact(secret);
        }
        if (rule.numberGroup() != null) {
            Long value = parseLong(matcher.group(rule.numberGroup()));
            if (value == null || value >= rule.below()) {
                return Optional.empty();
            }
            evidence = value + " (< " + rule.below() + ")";
        }
        if (rule.listCheck() != null) {
            String list = Optional.ofNullable(matcher.group(rule.listGroup())).orElse("");
            switch (rule.listCheck()) {
                case CIPHER_SUITES -> {
                    List<CipherSuitePolicy.Verdict> weak = ruleSet.cipherSuites().weakSuites(list);
                    if (weak.isEmpty()) {
                        return Optional.empty();
                    }
                    severity = weak.stream().map(CipherSuitePolicy.Verdict::severity).reduce(Severity.NONE, Severity::worst);
                    evidence = weak.stream().map(CipherSuitePolicy.Verdict::suite).collect(Collectors.joining(", "));
                    detail = weak.stream().map(v -> v.suite() + " : " + v.reason()).collect(Collectors.joining(" ; "));
                }
                case REQUIRE_ALL -> {
                    List<String> entries = LIST_SEPARATOR.splitAsStream(list).map(String::strip)
                            .filter(e -> !e.isEmpty()).toList();
                    List<String> missing = rule.required().stream()
                            .filter(r -> entries.stream().noneMatch(e -> e.equalsIgnoreCase(r)
                                    || e.toUpperCase(Locale.ROOT).startsWith(r.toUpperCase(Locale.ROOT) + " ")))
                            .toList();
                    if (missing.isEmpty()) {
                        return Optional.empty();
                    }
                    evidence = "manquant(s) : " + String.join(", ", missing);
                }
            }
        }
        return Optional.of(new Match(severity, evidence, detail));
    }

    private record Match(Severity severity, String evidence, String detail) {
    }

    private SecurityFinding finding(FindingRule rule, Source source, SourceText text, int line, int column,
                                    Match match) {
        String snippet = text.snippet(line);
        if (rule.secretGroup() != null) {
            snippet = redactLine(rule, snippet);
        }
        String description = match.detail() == null ? rule.description()
                : (rule.description() == null ? "" : rule.description() + " ") + match.detail();
        Severity severity = source.testCode() ? match.severity().lower() : match.severity();
        return new SecurityFinding(id(rule.id(), source, line), rule.id(), rule.category(), severity,
                rule.title(), description, rule.recommendation(), rule.cwe(), source.path(), line, column, snippet,
                match.evidence(), source.language(), source.testCode(), source.commit());
    }

    private SecurityFinding fileFinding(FindingRule rule, Source source) {
        return new SecurityFinding(id(rule.id(), source, 0), rule.id(), rule.category(),
                source.testCode() ? rule.severity().lower() : rule.severity(), rule.title(), rule.description(),
                rule.recommendation(), rule.cwe(), source.path(), null, null, null, null, fileLanguage(source),
                source.testCode(), source.commit());
    }

    /** Un fichier sans langage (keystore, .env) garde un langage absent, comme avant. */
    private static Language fileLanguage(Source source) {
        return source.language() == Language.UNKNOWN ? null : source.language();
    }

    /** L'identifiant d'un constat de l'historique porte le commit : il ne se confond pas avec l'état actuel. */
    private static String id(String ruleId, Source source, int line) {
        return id(ruleId, source.commit() == null ? source.path() : source.path() + "@" + source.commit(), line);
    }

    private static String fileName(String path) {
        return path.substring(path.lastIndexOf('/') + 1);
    }

    /** Recherche à nouveau le secret dans l'extrait pour le caviarder, quelle que soit sa position. */
    private static String redactLine(FindingRule rule, String snippet) {
        Matcher matcher = rule.pattern().matcher(snippet);
        StringBuilder out = new StringBuilder();
        int last = 0;
        while (matcher.find()) {
            String secret = matcher.group(rule.secretGroup());
            if (secret == null) {
                continue;
            }
            out.append(snippet, last, matcher.start(rule.secretGroup())).append(redact(secret));
            last = matcher.end(rule.secretGroup());
        }
        if (last == 0) {
            // Motif multi-lignes ou tronqué : on ne montre pas la ligne plutôt que risquer une fuite.
            return "[extrait masqué : secret]";
        }
        return out.append(snippet.substring(last)).toString();
    }

    static String redact(String secret) {
        int visible = Math.min(VISIBLE_SECRET_PREFIX, secret.length() / 2);
        return secret.substring(0, visible) + "...(" + secret.length() + " car.)";
    }

    private static boolean isTextMaterial(String fileName) {
        String lower = fileName.toLowerCase(Locale.ROOT);
        return lower.endsWith(".pem") || lower.endsWith(".key") || lower.startsWith("id_");
    }

    private static Long parseLong(String value) {
        if (value == null) {
            return null;
        }
        try {
            return Long.parseLong(value.replace("_", "").trim());
        } catch (NumberFormatException e) {
            return null;
        }
    }

    private static void add(Map<String, SecurityFinding> findings, SecurityFinding finding) {
        findings.putIfAbsent(finding.id(), finding);
    }

    static String id(String ruleId, String file, int line) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest((ruleId + '\u0000' + file + '\u0000' + line).getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(digest).substring(0, ID_HEX_LENGTH);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 indisponible", e);
        }
    }
}
