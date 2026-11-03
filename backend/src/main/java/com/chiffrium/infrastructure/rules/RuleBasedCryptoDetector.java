package com.chiffrium.infrastructure.rules;

import com.chiffrium.application.port.CryptoDetector;
import com.chiffrium.application.port.ProjectScanner.ScannedFile;
import com.chiffrium.domain.asset.AssetFactory;
import com.chiffrium.domain.asset.CryptoFunctionHints;
import com.chiffrium.domain.model.AlgorithmSpec;
import com.chiffrium.domain.model.CryptoAsset;
import com.chiffrium.infrastructure.scan.FileFailures;
import com.chiffrium.domain.model.CryptoFunction;
import com.chiffrium.domain.model.DetectionSource;
import com.chiffrium.domain.model.Language;
import com.chiffrium.domain.model.Occurrence;
import com.chiffrium.domain.model.Primitive;
import com.chiffrium.infrastructure.scan.FileClassifier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.function.Supplier;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Détecteur multi-langages fondé sur des règles déclaratives (src/main/resources/rules/*.json).
 * Il complète cdxgen, dont l'analyse cryptographique ne couvre que Java et Python.
 *
 * <p>Pour chaque fichier : application des règles d'algorithmes (de la plus spécifique à la plus générique,
 * sans double lecture d'une même zone), résolution des arguments (littéraux, constantes, concaténations),
 * rattachement des tailles de clé / modes / bourrages / courbes à la détection précédente la plus proche,
 * relevé des lectures/écritures de fichiers de clés, puis qualification par la fonction englobante.
 */
public final class RuleBasedCryptoDetector implements CryptoDetector {

    private static final Logger LOG = LoggerFactory.getLogger(RuleBasedCryptoDetector.class);

    static final int MAX_ATTACH_DISTANCE_LINES = 20;
    private static final Pattern LIST_SEPARATOR = Pattern.compile("[\\s,:;|]+");
    private static final Pattern TEMPLATE_PLACEHOLDER = Pattern.compile("\\{(\\w+)}");
    private static final Pattern QUOTED = Pattern.compile("^[bBrRuUfF@]{0,2}([\"'`])(.*)\\1$");
    private static final Set<String> WRITE_HINTS = Set.of("write", "create", "put", "save", "dump", "export", "append");
    private static final List<String> MATERIAL_NAME_HINTS = List.of(
            "key", "cert", "secret", "private", "public", "keystore", "truststore", "pem", "cipher", "encrypted",
            ".enc", ".sig", "signature", "token");
    private static final Set<Primitive> SIZED_PRIMITIVES = EnumSet.of(Primitive.PUBLIC_KEY_ENCRYPTION,
            Primitive.SIGNATURE, Primitive.KEY_AGREEMENT, Primitive.OTHER, Primitive.BLOCK_CIPHER,
            Primitive.AUTHENTICATED_ENCRYPTION, Primitive.STREAM_CIPHER, Primitive.KEM);
    private static final Set<Primitive> OVERRIDABLE_PRIMITIVES = EnumSet.of(Primitive.UNKNOWN, Primitive.OTHER,
            Primitive.PUBLIC_KEY_ENCRYPTION);
    private static final Set<Primitive> MODE_PRIMITIVES = EnumSet.of(Primitive.BLOCK_CIPHER,
            Primitive.AUTHENTICATED_ENCRYPTION);

    private final List<RulePack> packs;
    private final AssetFactory assetFactory;

    public RuleBasedCryptoDetector(List<RulePack> packs, AssetFactory assetFactory) {
        this.packs = List.copyOf(packs);
        this.assetFactory = assetFactory;
    }

    @Override
    public String name() {
        return "règles";
    }

    @Override
    public DetectionResult detect(DetectionContext context) {
        List<ScannedFile> sources = context.scan().files().stream()
                .filter(f -> f.language() != null && packs.stream().anyMatch(p -> p.appliesTo(f.language())))
                .toList();
        // Un index de constantes par paquet de règles : une constante JavaScript ne doit pas résoudre du Java.
        Map<String, ConstantResolver> resolvers = new HashMap<>();
        for (RulePack pack : packs) {
            List<ScannedFile> packFiles = sources.stream().filter(f -> pack.appliesTo(f.language())).toList();
            resolvers.put(pack.id(), new ConstantResolver(memoize(() -> buildProjectIndex(context.projectRoot(), packFiles))));
        }
        List<CryptoAsset> assets = new ArrayList<>();
        List<FileFlow> flows = new ArrayList<>();
        List<String> warnings = new ArrayList<>();
        int unresolved = 0;
        FileFailures failures = new FileFailures(name());

        for (ScannedFile file : sources) {
            Optional<SourceText> text = read(context.projectRoot().resolve(file.path()), file.path(), warnings);
            if (text.isEmpty()) {
                continue;
            }
            for (RulePack pack : packs) {
                if (!pack.appliesTo(file.language())) {
                    continue;
                }
                FileAnalysis analysis = new FileAnalysis(pack, file, text.get(), resolvers.get(pack.id()));
                try {
                    analysis.run();
                } catch (RuntimeException | StackOverflowError e) {
                    failures.record(file.path(), e);
                    continue;
                }
                for (Detection detection : analysis.detections) {
                    Occurrence occurrence = new Occurrence(file.path(), detection.line, detection.column,
                            detection.function, text.get().snippet(detection.line), file.language(),
                            DetectionSource.RULES, detection.ruleId, detection.functions);
                    if (detection.unresolvedApi != null) {
                        unresolved++;
                        assets.add(assetFactory.unresolved(detection.unresolvedApi, occurrence, detection.functions));
                    } else {
                        assets.add(assetFactory.fromSpec(detection.spec, occurrence, detection.functions,
                                DetectionSource.RULES, null));
                    }
                }
                flows.addAll(analysis.flows);
            }
        }
        if (unresolved > 0) {
            warnings.add(unresolved + " appel(s) d'API cryptographique avec un algorithme non résolu statiquement "
                    + "(à vérifier manuellement).");
        }
        warnings.addAll(failures.warnings());
        return new DetectionResult(assets, flows, warnings);
    }

    private Optional<SourceText> read(Path path, String relative, List<String> warnings) {
        try {
            Optional<SourceText> text = SourceText.load(path);
            if (text.isEmpty()) {
                LOG.debug("Fichier binaire, minifié ou généré ignoré : {}", relative);
            }
            return text;
        } catch (IOException e) {
            warnings.add("Lecture impossible : " + relative);
            return Optional.empty();
        }
    }

    private static Map<String, List<String>> buildProjectIndex(Path root, List<ScannedFile> files) {
        List<String> contents = new ArrayList<>();
        for (ScannedFile file : files) {
            try {
                contents.add(Files.readString(root.resolve(file.path()), StandardCharsets.UTF_8));
            } catch (IOException e) {
                LOG.debug("Fichier ignoré pour l'index des constantes : {}", file.path());
            }
        }
        return ConstantResolver.buildIndex(contents);
    }

    private static <T> Supplier<T> memoize(Supplier<T> supplier) {
        return new Supplier<>() {
            private T value;

            @Override
            public synchronized T get() {
                if (value == null) {
                    value = supplier.get();
                }
                return value;
            }
        };
    }

    /** Détection en cours de construction (modifiable jusqu'au rattachement des paramètres). */
    private static final class Detection {
        private AlgorithmSpec spec;
        private final int line;
        private final int column;
        private final String function;
        private final Set<CryptoFunction> functions;
        private final String ruleId;
        private final String unresolvedApi;

        Detection(AlgorithmSpec spec, int line, int column, String function, Set<CryptoFunction> functions,
                  String ruleId, String unresolvedApi) {
            this.spec = spec;
            this.line = line;
            this.column = column;
            this.function = function;
            this.functions = functions;
            this.ruleId = ruleId;
            this.unresolvedApi = unresolvedApi;
        }
    }

    private record Modifier(Rule.Kind kind, int line, String function, String value) {
    }

    /**
     * Analyse d'un fichier par un paquet de règles.
     */
    private final class FileAnalysis {
        private final RulePack pack;
        private final ScannedFile file;
        private final SourceText text;
        private final ConstantResolver resolver;
        private final ScopeResolver scopes;
        private final String fileStem;
        private final List<int[]> consumed = new ArrayList<>();
        private final List<Modifier> modifiers = new ArrayList<>();
        private final Map<Integer, String> functionCache = new HashMap<>();
        private final List<Detection> detections = new ArrayList<>();
        private final List<FileFlow> flows = new ArrayList<>();

        FileAnalysis(RulePack pack, ScannedFile file, SourceText text, ConstantResolver resolver) {
            this.pack = pack;
            this.file = file;
            this.text = text;
            this.resolver = resolver;
            RulePack scopePack = scopePackFor(file.language(), pack);
            this.scopes = new ScopeResolver(scopePack.functionPatterns(), scopePack.classPatterns(),
                    ScopeResolver.BlockStyle.of(scopePack.blockStyle()));
            String name = file.path().substring(file.path().lastIndexOf('/') + 1);
            int dot = name.indexOf('.');
            this.fileStem = dot > 0 ? name.substring(0, dot) : name;
        }

        void run() {
            for (Rule rule : pack.rules()) {
                Matcher matcher = rule.pattern().matcher(text.content());
                while (matcher.find()) {
                    int line = text.lineOf(matcher.start());
                    if (text.isCommentLine(line, pack.commentPrefixes())) {
                        continue;
                    }
                    switch (rule.kind()) {
                        case ALGORITHM -> onAlgorithm(rule, matcher, line);
                        case FILE -> onFile(rule, matcher, line);
                        default -> onModifier(rule, matcher, line);
                    }
                }
            }
            modifiers.forEach(this::attach);
        }

        private void onAlgorithm(Rule rule, Matcher matcher, int line) {
            if (overlapsConsumed(matcher.start(), matcher.end())) {
                return;
            }
            consumed.add(new int[]{matcher.start(), matcher.end()});
            String api = firstGroup(matcher, "api", "op");
            Set<CryptoFunction> functions = functionsOf(rule, api);
            Primitive primitiveHint = api != null && rule.primitiveByApi().containsKey(api)
                    ? rule.primitiveByApi().get(api) : rule.primitive();
            Integer keySize = parseSize(group(matcher, "size"));
            int column = text.columnOf(matcher.start());
            String function = functionAt(line);

            for (Candidate candidate : candidates(rule, matcher)) {
                if (candidate.raw == null) {
                    String apiName = api != null ? api : rule.id();
                    detections.add(new Detection(null, line, column, function, functions, rule.id(), apiName));
                    continue;
                }
                AlgorithmSpec spec = assetFactory.normalizer().normalize(candidate.raw);
                if (!spec.isRecognized() && rule.skipUnrecognized()) {
                    continue;
                }
                if (keySize != null && spec.keySize() == null) {
                    spec = spec.withKeySize(keySize);
                }
                if (primitiveHint != null && OVERRIDABLE_PRIMITIVES.contains(spec.primitive())) {
                    spec = spec.withPrimitive(primitiveHint);
                }
                detections.add(new Detection(spec, line, column, function, functions, rule.id(), null));
            }
        }

        private void onModifier(Rule rule, Matcher matcher, int line) {
            String value = switch (rule.kind()) {
                case KEYSIZE -> group(matcher, "size");
                case MODE -> Optional.ofNullable(group(matcher, "mode")).orElse(rule.algorithm());
                case PADDING -> Optional.ofNullable(group(matcher, "padding")).orElse(rule.algorithm());
                case CURVE -> group(matcher, "curve");
                default -> null;
            };
            if (value != null) {
                modifiers.add(new Modifier(rule.kind(), line, functionAt(line), mapped(rule, stripQuotes(value))));
            }
        }

        private void onFile(Rule rule, Matcher matcher, int line) {
            Optional<String> resolved = resolver.resolve(group(matcher, "file"), text.content());
            if (resolved.isEmpty()) {
                return;
            }
            String path = resolved.get().replace('\\', '/');
            String baseName = path.substring(path.lastIndexOf('/') + 1);
            if (baseName.isBlank() || !isMaterialLike(baseName)) {
                return;
            }
            flows.add(new FileFlow(baseName, file.path(), line, functionAt(line), isWrite(rule, matcher)));
        }

        /** Rattache un paramètre à la détection précédente compatible la plus proche. */
        private void attach(Modifier modifier) {
            Detection target = null;
            for (Detection detection : detections) {
                boolean candidate = detection.spec != null
                        && detection.line <= modifier.line()
                        && modifier.line() - detection.line <= MAX_ATTACH_DISTANCE_LINES
                        && (detection.function == null || modifier.function() == null
                        || detection.function.equals(modifier.function()))
                        && accepts(detection.spec, modifier.kind());
                if (candidate && (target == null || detection.line >= target.line)) {
                    target = detection;
                }
            }
            if (target == null) {
                return;
            }
            AlgorithmSpec old = target.spec;
            AlgorithmSpec updated = switch (modifier.kind()) {
                case KEYSIZE -> Optional.ofNullable(parseSize(modifier.value())).map(old::withKeySize).orElse(old);
                case MODE, PADDING -> renormalize(old, old.rawName() + "/" + modifier.value());
                case CURVE -> renormalize(old, old.rawName() + "-" + modifier.value());
                default -> old;
            };
            target.spec = updated;
        }

        private AlgorithmSpec renormalize(AlgorithmSpec old, String raw) {
            AlgorithmSpec updated = assetFactory.normalizer().normalize(raw);
            if (!old.catalogId().equals(updated.catalogId())) {
                return old;
            }
            if (updated.keySize() == null && old.keySize() != null) {
                updated = updated.withKeySize(old.keySize());
            }
            return updated.withPrimitive(old.primitive());
        }

        private boolean accepts(AlgorithmSpec spec, Rule.Kind kind) {
            return switch (kind) {
                case KEYSIZE -> spec.keySize() == null && SIZED_PRIMITIVES.contains(spec.primitive());
                case MODE -> spec.mode() == null && MODE_PRIMITIVES.contains(spec.primitive());
                case PADDING -> spec.padding() == null;
                case CURVE -> spec.curve() == null;
                default -> false;
            };
        }

        /** Noms bruts à normaliser pour une correspondance ; null = argument non résolu. */
        private List<Candidate> candidates(Rule rule, Matcher matcher) {
            if (rule.template() != null) {
                String filled = fillTemplate(rule, matcher);
                return List.of(new Candidate(filled == null ? null : withParameters(filled, rule, matcher)));
            }
            if (rule.algorithm() != null) {
                return List.of(new Candidate(withParameters(rule.algorithm(), rule, matcher)));
            }
            String list = group(matcher, "list");
            if (list != null) {
                List<Candidate> items = new ArrayList<>();
                for (String item : LIST_SEPARATOR.split(list)) {
                    String cleaned = stripQuotes(item.trim()).replaceFirst("^\\+", "");
                    if (!cleaned.isEmpty() && !cleaned.startsWith("-") && !cleaned.startsWith("!")
                            && !"all".equalsIgnoreCase(cleaned)) {
                        items.add(new Candidate(mapped(rule, cleaned)));
                    }
                }
                return items;
            }
            String primary = group(matcher, "name");
            if (primary == null) {
                primary = resolveArgument(group(matcher, "algo"));
                if (primary == null) {
                    return List.of(new Candidate(null));
                }
            }
            return List.of(new Candidate(withParameters(mapped(rule, primary), rule, matcher)));
        }

        /** Ajoute au nom les paramètres capturés que le gabarit n'utilise pas déjà. */
        private String withParameters(String base, Rule rule, Matcher matcher) {
            StringBuilder raw = new StringBuilder(base);
            for (String[] parameter : new String[][]{{"mode", "/"}, {"padding", "/"}, {"curve", "-"}}) {
                boolean inTemplate = rule.template() != null && rule.template().contains("{" + parameter[0] + "}");
                String value = group(matcher, parameter[0]);
                if (!inTemplate && value != null) {
                    appendIfPresent(raw, parameter[1], mapped(rule, stripQuotes(value)));
                }
            }
            return raw.toString();
        }

        private String fillTemplate(Rule rule, Matcher matcher) {
            Matcher placeholder = TEMPLATE_PLACEHOLDER.matcher(rule.template());
            StringBuilder result = new StringBuilder();
            while (placeholder.find()) {
                String name = placeholder.group(1);
                String value = "algo".equals(name) ? resolveArgument(group(matcher, name)) : group(matcher, name);
                if ("algo".equals(name) && value == null && group(matcher, name) != null) {
                    return null;
                }
                placeholder.appendReplacement(result, Matcher.quoteReplacement(
                        value == null ? "" : mapped(rule, stripQuotes(value))));
            }
            placeholder.appendTail(result);
            return mapped(rule, result.toString());
        }

        /**
         * Résout un argument ; si c'est un identifiant non résolu dont le dernier segment est lui-même un nom
         * d'algorithme (ex. {@code Algorithms.AES_GCM}, {@code KeyProperties.KEY_ALGORITHM_RSA}), on le retient.
         */
        private String resolveArgument(String expression) {
            if (expression == null) {
                return null;
            }
            Optional<String> resolved = resolver.resolve(expression, text.content());
            if (resolved.isPresent()) {
                return resolved.get();
            }
            if (!ConstantResolver.isLiteral(expression)) {
                String segment = ConstantResolver.lastSegment(expression.trim());
                if (assetFactory.normalizer().normalize(segment).isRecognized()) {
                    return segment;
                }
            }
            return null;
        }

        private Set<CryptoFunction> functionsOf(Rule rule, String api) {
            List<CryptoFunction> declared = api != null && rule.functionsByApi().containsKey(api)
                    ? rule.functionsByApi().get(api) : rule.functions();
            if (!declared.isEmpty()) {
                return EnumSet.copyOf(declared);
            }
            return CryptoFunctionHints.fromCallName(api);
        }

        private String functionAt(int line) {
            return functionCache.computeIfAbsent(line, l -> scopes.qualifiedFunction(text, l, fileStem));
        }

        private boolean overlapsConsumed(int start, int end) {
            return consumed.stream().anyMatch(range -> start < range[1] && end > range[0]);
        }

        private boolean isWrite(Rule rule, Matcher matcher) {
            String mode = group(matcher, "mode");
            if (mode != null) {
                String cleaned = stripQuotes(mode).toLowerCase(Locale.ROOT);
                return cleaned.contains("w") || cleaned.contains("a") || cleaned.contains("x");
            }
            String op = group(matcher, "op");
            if (op != null) {
                String lower = op.toLowerCase(Locale.ROOT);
                return WRITE_HINTS.stream().anyMatch(lower::contains);
            }
            return "write".equalsIgnoreCase(rule.direction());
        }
    }

    private record Candidate(String raw) {
    }

    /**
     * Paquet fournissant les motifs de déclaration du langage : un paquet transverse (ex. JWT) réutilise
     * ceux du paquet principal du langage.
     */
    private RulePack scopePackFor(Language language, RulePack current) {
        if (!current.functionPatterns().isEmpty()) {
            return current;
        }
        return packs.stream()
                .filter(p -> p.appliesTo(language) && !p.functionPatterns().isEmpty())
                .findFirst()
                .orElse(current);
    }

    private static boolean isMaterialLike(String baseName) {
        String lower = baseName.toLowerCase(Locale.ROOT);
        return FileClassifier.isMaterial(baseName) || MATERIAL_NAME_HINTS.stream().anyMatch(lower::contains);
    }

    private static String mapped(Rule rule, String value) {
        if (value == null) {
            return null;
        }
        return rule.map().getOrDefault(value.toLowerCase(Locale.ROOT), value);
    }

    private static void appendIfPresent(StringBuilder builder, String separator, String value) {
        if (value != null && !value.isBlank()) {
            builder.append(separator).append(stripQuotes(value));
        }
    }

    private static String group(Matcher matcher, String name) {
        if (!matcher.pattern().namedGroups().containsKey(name)) {
            return null;
        }
        String value = matcher.group(name);
        return value == null || value.isBlank() ? null : value.trim();
    }

    private static String firstGroup(Matcher matcher, String... names) {
        for (String name : names) {
            String value = group(matcher, name);
            if (value != null) {
                return value;
            }
        }
        return null;
    }

    private static String stripQuotes(String value) {
        String trimmed = value.trim();
        Matcher quoted = QUOTED.matcher(trimmed);
        return quoted.matches() ? quoted.group(2) : trimmed;
    }

    private static Integer parseSize(String value) {
        if (value == null || !value.chars().allMatch(Character::isDigit) || value.isEmpty()) {
            return null;
        }
        int size = Integer.parseInt(value);
        return size > 0 ? size : null;
    }

    /** Pour les tests : langages couverts par les règles chargées. */
    Set<Language> coveredLanguages() {
        Set<Language> languages = EnumSet.noneOf(Language.class);
        packs.forEach(p -> languages.addAll(p.languages()));
        return languages;
    }
}
