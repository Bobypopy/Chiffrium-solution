package com.chiffrium.infrastructure.rules;

import com.chiffrium.application.port.CallEdgeExtractor.CallEdge;
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
import java.util.Comparator;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.function.Supplier;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * Détecteur multi-langages fondé sur des règles déclaratives (src/main/resources/rules/*.json).
 * Il complète cdxgen, dont l'analyse cryptographique ne couvre que Java et Python.
 *
 * <p>Pour chaque fichier : application des règles d'algorithmes (de la plus spécifique à la plus générique,
 * sans double lecture d'une même zone), résolution des arguments (littéraux, constantes, concaténations),
 * rattachement des tailles de clé / modes / bourrages / courbes à la détection précédente la plus proche,
 * relevé des lectures/écritures de fichiers de clés, puis qualification par la fonction englobante.
 * Une règle qui déclare le type de clé qu'elle crée ({@code key}) inventorie aussi la clé générée.
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
    private static final String SECRET_KEY = "secret-key";
    private static final String PRIVATE_KEY = "private-key";
    private static final String AUTO_KEY = "auto";
    private static final Set<Primitive> SYMMETRIC_KEY_PRIMITIVES = EnumSet.of(Primitive.BLOCK_CIPHER,
            Primitive.STREAM_CIPHER, Primitive.AUTHENTICATED_ENCRYPTION, Primitive.MAC);

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
        // Un index par paquet de règles : une constante ou une fonction JavaScript ne doit pas résoudre du Java.
        // Les paquets d'un langage (qui déclarent ses fonctions) indexent aussi les appels, pour la trace et le graphe.
        Map<String, ConstantResolver> resolvers = new HashMap<>();
        Map<String, Supplier<ProjectCode>> codes = new HashMap<>();
        Map<String, Supplier<ValueTracer>> tracers = new HashMap<>();
        for (RulePack pack : packs) {
            List<ScannedFile> packFiles = sources.stream().filter(f -> pack.appliesTo(f.language())).toList();
            if (pack.functionPatterns().isEmpty()) {
                resolvers.put(pack.id(), new ConstantResolver(memoize(() -> buildProjectIndex(context.projectRoot(), packFiles))));
                continue;
            }
            Supplier<ProjectCode> code = memoize(() -> ProjectCode.load(context.projectRoot(), packFiles,
                    language -> scopePackFor(language, pack)));
            ConstantResolver resolver = new ConstantResolver(() -> code.get().constants());
            codes.put(pack.id(), code);
            resolvers.put(pack.id(), resolver);
            tracers.put(pack.id(), memoize(() -> new ValueTracer(code.get(), resolver)));
        }
        List<CryptoAsset> assets = new ArrayList<>();
        List<FileFlow> flows = new ArrayList<>();
        List<String> warnings = new ArrayList<>();
        Map<String, Origin> traceOrigins = new LinkedHashMap<>();
        Set<String> packsWithCrypto = new HashSet<>();
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
                FileAnalysis analysis = new FileAnalysis(pack, file, text.get(), resolvers.get(pack.id()),
                        tracers.get(pack.id()));
                try {
                    analysis.run();
                } catch (RuntimeException | StackOverflowError e) {
                    failures.record(file.path(), e);
                    continue;
                }
                for (Detection detection : analysis.detections) {
                    Occurrence occurrence = new Occurrence(file.path(), detection.line, detection.column,
                            detection.function, text.get().snippet(detection.line), file.language(),
                            DetectionSource.RULES, detection.ruleId, detection.functions,
                            detection.provenance.mainPath(), detection.provenance.otherPaths());
                    CryptoAsset algorithm;
                    if (detection.unresolvedApi != null) {
                        unresolved++;
                        algorithm = assetFactory.unresolved(detection.unresolvedApi, occurrence, detection.functions);
                    } else {
                        algorithm = assetFactory.fromSpec(detection.spec, occurrence, detection.functions,
                                DetectionSource.RULES, null);
                    }
                    assets.add(algorithm);
                    for (String origin : detection.provenance.origins()) {
                        traceOrigins.putIfAbsent(origin, new Origin(algorithm.algorithm(), pack.id(), detection.ruleId));
                    }
                    // La clé est inventoriée même si son algorithme est inconnu ou non résolu : elle sera "à vérifier".
                    if (detection.key != null) {
                        assets.add(assetFactory.generatedKey(keyType(detection.key, algorithm.algorithm()),
                                algorithm.algorithm(), occurrence));
                    }
                }
                flows.addAll(analysis.flows);
                if (!analysis.detections.isEmpty() || !analysis.flows.isEmpty()) {
                    packsWithCrypto.add(pack.id());
                }
            }
        }
        attachTracedOrigins(assets, traceOrigins, codes);
        List<CallEdge> callEdges = new ArrayList<>();
        packsWithCrypto.stream().filter(codes::containsKey).forEach(id -> callEdges.addAll(codes.get(id).get().callEdges()));
        if (unresolved > 0) {
            warnings.add(unresolved + " appel(s) d'API cryptographique avec un algorithme non résolu statiquement "
                    + "(à vérifier manuellement).");
        }
        warnings.addAll(failures.warnings());
        return new DetectionResult(assets, flows, warnings, List.of(), callEdges);
    }

    /** Endroit où une valeur tracée est écrite : l'actif qui l'utilise, et la règle et le paquet de l'appel. */
    private record Origin(AlgorithmSpec spec, String packId, String ruleId) {
    }

    /**
     * L'endroit où une valeur tracée est écrite devient un emplacement de l'actif de l'appel qui l'utilise : un
     * actif, là où la valeur est écrite et là où elle sert. Un nom écrit seul (règle de repli) qui y était déjà
     * inventorié n'est pas un second algorithme ("DES" écrit dans Main, utilisé comme "DES/ECB/PKCS5Padding" par
     * Cipher) ; un nombre ou un nom non retenu seul ("IDEA", 'md5') reçoit un emplacement.
     */
    private void attachTracedOrigins(List<CryptoAsset> assets, Map<String, Origin> traceOrigins,
                                     Map<String, Supplier<ProjectCode>> codes) {
        if (traceOrigins.isEmpty()) {
            return;
        }
        Set<String> fallbackRules = packs.stream().flatMap(p -> p.rules().stream()).filter(Rule::fallback)
                .map(Rule::id).collect(Collectors.toSet());
        assets.replaceAll(asset -> {
            if (asset.occurrences().size() != 1 || !fallbackRules.contains(asset.occurrences().get(0).ruleId())) {
                return asset;
            }
            Occurrence occurrence = asset.occurrences().get(0);
            Origin origin = traceOrigins.get(occurrence.locationKey());
            return origin == null ? asset
                    : assetFactory.fromSpec(origin.spec(), occurrence, asset.functions(), DetectionSource.RULES, null);
        });
        Set<String> located = new HashSet<>();
        assets.forEach(a -> a.occurrences().forEach(o -> located.add(o.locationKey() + "|"
                + (a.algorithm() == null ? null : a.algorithm().catalogId()))));
        traceOrigins.forEach((location, origin) -> {
            if (located.contains(location + "|" + origin.spec().catalogId()) || !codes.containsKey(origin.packId())) {
                return;
            }
            ProjectCode code = codes.get(origin.packId()).get();
            int colon = location.lastIndexOf(':');
            String path = location.substring(0, colon);
            int line = Integer.parseInt(location.substring(colon + 1));
            code.text(path).ifPresent(text -> {
                ProjectCode.FunctionDef function = code.functionAt(path, line);
                Occurrence occurrence = new Occurrence(path, line, null,
                        function == null ? null : function.qualified(), text.snippet(line), code.language(path),
                        DetectionSource.RULES, origin.ruleId(), Set.of());
                assets.add(assetFactory.fromSpec(origin.spec(), occurrence, Set.of(), DetectionSource.RULES, null));
            });
        });
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
        /** Type de la clé créée à cet endroit ("private-key", "secret-key"), null si aucune. */
        private final String key;
        /** Trajets des valeurs retrouvées par {@link ValueTracer} (algorithme, taille), vide si écrites sur place. */
        private Provenance provenance = Provenance.NONE;

        Detection(AlgorithmSpec spec, int line, int column, String function, Set<CryptoFunction> functions,
                  String ruleId, String unresolvedApi, String key) {
            this.spec = spec;
            this.line = line;
            this.column = column;
            this.function = function;
            this.functions = functions;
            this.ruleId = ruleId;
            this.unresolvedApi = unresolvedApi;
            this.key = key;
        }
    }

    /**
     * Provenance d'une valeur venue d'ailleurs.
     *
     * @param paths   trajets, chacun de l'endroit où la valeur est écrite jusqu'au dernier relais
     * @param origins emplacements ("fichier:ligne") où elle est écrite telle quelle
     */
    private record Provenance(List<List<String>> paths, List<String> origins) {

        static final Provenance NONE = new Provenance(List.of(), List.of());

        static Provenance of(ValueTracer.Traced traced) {
            return new Provenance(traced.paths(), traced.origins());
        }

        Provenance plus(Provenance other) {
            List<List<String>> allPaths = new ArrayList<>(paths);
            allPaths.addAll(other.paths);
            List<String> allOrigins = new ArrayList<>(origins);
            allOrigins.addAll(other.origins);
            return new Provenance(List.copyOf(allPaths), List.copyOf(allOrigins));
        }

        List<String> mainPath() {
            return paths.isEmpty() ? List.of() : paths.get(0);
        }

        /** Autres trajets, chacun en une ligne ("A (f:1) → B (g:2)"). */
        List<String> otherPaths() {
            return paths.stream().skip(1).map(path -> String.join(" → ", path)).toList();
        }
    }

    /** @param provenance trajet d'une taille venue d'ailleurs (paramètre, champ) */
    private record Modifier(Rule.Kind kind, int line, int column, String function, String value, String ruleId,
                            Provenance provenance) {
    }

    /** Taille de clé et provenance de sa valeur quand elle vient d'ailleurs. */
    private record Sized(Integer value, Provenance provenance) {
    }

    /**
     * Analyse d'un fichier par un paquet de règles.
     */
    private final class FileAnalysis {
        private final RulePack pack;
        private final ScannedFile file;
        private final SourceText text;
        private final ConstantResolver resolver;
        /** Null pour un paquet transverse (JWT, KMS) : sans déclarations de fonctions, rien à remonter. */
        private final Supplier<ValueTracer> tracer;
        private final ScopeResolver scopes;
        private final List<String> commentPrefixes;
        private final String fileStem;
        private final List<int[]> consumed = new ArrayList<>();
        private final List<Modifier> modifiers = new ArrayList<>();
        private final Map<Integer, String> functionCache = new HashMap<>();
        private final List<Detection> detections = new ArrayList<>();
        private final List<FileFlow> flows = new ArrayList<>();

        FileAnalysis(RulePack pack, ScannedFile file, SourceText text, ConstantResolver resolver,
                     Supplier<ValueTracer> tracer) {
            this.pack = pack;
            this.file = file;
            this.text = text;
            this.resolver = resolver;
            this.tracer = tracer;
            RulePack scopePack = scopePackFor(file.language(), pack);
            this.scopes = new ScopeResolver(scopePack.functionPatterns(), scopePack.classPatterns(),
                    ScopeResolver.BlockStyle.of(scopePack.blockStyle()));
            // Règles empruntées (VB.NET lu par le paquet C#) : les commentaires sont ceux du langage du fichier.
            this.commentPrefixes = scopePack != pack && !pack.functionPatterns().isEmpty()
                    ? scopePack.commentPrefixes() : pack.commentPrefixes();
            String name = file.path().substring(file.path().lastIndexOf('/') + 1);
            int dot = name.indexOf('.');
            this.fileStem = dot > 0 ? name.substring(0, dot) : name;
        }

        void run() {
            for (Rule rule : pack.rules()) {
                Matcher matcher = rule.pattern().matcher(text.content());
                while (matcher.find()) {
                    int line = text.lineOf(matcher.start());
                    if (text.isCommentLine(line, commentPrefixes)) {
                        continue;
                    }
                    switch (rule.kind()) {
                        case ALGORITHM -> onAlgorithm(rule, matcher, line);
                        case FILE -> onFile(rule, matcher, line);
                        default -> onModifier(rule, matcher, line);
                    }
                }
            }
            // Les tailles en octets viennent en dernier : la clé générée reprend la détection déjà complétée.
            modifiers.stream().filter(m -> m.kind() != Rule.Kind.KEYBYTES).forEach(this::attach);
            modifiers.stream().filter(m -> m.kind() == Rule.Kind.KEYBYTES).forEach(this::attach);
            dropRedundantFallbacks();
        }

        /**
         * Un nom d'algorithme écrit seul (règle de repli) signale une valeur transmise par un champ, une méthode
         * ou une autre classe ; si un appel reconnu du fichier dit déjà tout ce qu'il dit, il ferait doublon.
         * "AES/ECB/PKCS5Padding" reste donc à côté de {@code KeyGenerator.getInstance("AES")} : le mode est en plus.
         */
        private void dropRedundantFallbacks() {
            Set<String> fallbackRules = pack.rules().stream().filter(Rule::fallback).map(Rule::id)
                    .collect(Collectors.toSet());
            List<AlgorithmSpec> calls = detections.stream()
                    .filter(d -> d.spec != null && !fallbackRules.contains(d.ruleId))
                    .map(d -> d.spec)
                    .toList();
            detections.removeIf(d -> fallbackRules.contains(d.ruleId) && d.spec != null
                    && calls.stream().anyMatch(call -> covers(call, d.spec)));
        }

        private static boolean covers(AlgorithmSpec call, AlgorithmSpec named) {
            return Objects.equals(call.catalogId(), named.catalogId())
                    && (named.mode() == null || named.mode().equals(call.mode()))
                    && (named.padding() == null || named.padding().equals(call.padding()))
                    && (named.keySize() == null || named.keySize().equals(call.keySize()));
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
            Integer keySize = sizeOf(group(matcher, "size"), line).value();
            int column = text.columnOf(matcher.start());
            String function = functionAt(line);
            String key = api != null && rule.keyByApi().containsKey(api) ? rule.keyByApi().get(api) : rule.key();

            for (Candidate candidate : candidates(rule, matcher, line)) {
                if (candidate.raw == null) {
                    String apiName = api != null ? api : rule.id();
                    detections.add(new Detection(null, line, column, function, functions, rule.id(), apiName, key));
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
                Detection detection = new Detection(spec, line, column, function, functions, rule.id(), null, key);
                detection.provenance = candidate.provenance;
                detections.add(detection);
            }
        }

        private void onModifier(Rule rule, Matcher matcher, int line) {
            Sized size = rule.kind() == Rule.Kind.KEYSIZE ? sizeOf(group(matcher, "size"), line) : null;
            String value = switch (rule.kind()) {
                case KEYSIZE -> Optional.ofNullable(size.value()).map(String::valueOf).orElse(null);
                case KEYBYTES -> group(matcher, "size");
                case MODE -> Optional.ofNullable(group(matcher, "mode")).orElse(rule.algorithm());
                case PADDING -> Optional.ofNullable(group(matcher, "padding")).orElse(rule.algorithm());
                case CURVE -> group(matcher, "curve");
                default -> null;
            };
            if (value != null) {
                modifiers.add(new Modifier(rule.kind(), line, text.columnOf(matcher.start()), functionAt(line),
                        mapped(rule, stripQuotes(value)), rule.id(), size == null ? Provenance.NONE : size.provenance()));
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

        /**
         * Rattache un paramètre à la détection compatible la plus proche : au-dessus de lui, ou de part et d'autre
         * pour une clé tirée au hasard, qui devient alors une clé générée à son emplacement.
         */
        private void attach(Modifier modifier) {
            boolean keyBytes = modifier.kind() == Rule.Kind.KEYBYTES;
            Detection target = null;
            for (Detection detection : detections) {
                int distance = Math.abs(modifier.line() - detection.line);
                boolean candidate = detection.spec != null
                        && (keyBytes || detection.line <= modifier.line())
                        && distance <= MAX_ATTACH_DISTANCE_LINES
                        && (detection.function == null || modifier.function() == null
                        || detection.function.equals(modifier.function()))
                        && accepts(detection.spec, modifier.kind());
                if (candidate && (target == null || distance <= Math.abs(modifier.line() - target.line))) {
                    target = detection;
                }
            }
            if (target == null) {
                return;
            }
            AlgorithmSpec old = target.spec;
            AlgorithmSpec updated = switch (modifier.kind()) {
                case KEYSIZE -> Optional.ofNullable(parseSize(modifier.value())).map(old::withKeySize).orElse(old);
                case KEYBYTES -> Optional.ofNullable(parseSize(modifier.value()))
                        .map(bytes -> old.withKeySize(bytes * Byte.SIZE)).orElse(old);
                case MODE, PADDING -> renormalize(old, old.rawName() + "/" + modifier.value());
                case CURVE -> renormalize(old, old.rawName() + "-" + modifier.value());
                default -> old;
            };
            target.spec = updated;
            if (updated != old) {
                target.provenance = target.provenance.plus(modifier.provenance());
            }
            if (keyBytes) {
                detections.add(new Detection(updated, modifier.line(), modifier.column(), modifier.function(),
                        EnumSet.of(CryptoFunction.KEYGEN), modifier.ruleId(), null, SECRET_KEY));
            }
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
                // Seulement si la taille de clé varie (AES) : 32 octets de ChaCha20 n'apprennent rien.
                case KEYBYTES -> spec.keySize() == null && MODE_PRIMITIVES.contains(spec.primitive())
                        && assetFactory.normalizer().catalog().findAlgorithm(spec.catalogId())
                        .map(definition -> !definition.keySizeRules().isEmpty()).orElse(false);
                case MODE -> spec.mode() == null && MODE_PRIMITIVES.contains(spec.primitive());
                case PADDING -> spec.padding() == null;
                case CURVE -> spec.curve() == null;
                default -> false;
            };
        }

        /**
         * Noms bruts à normaliser pour une correspondance ; null = argument non résolu. Un argument que les
         * constantes ne résolvent pas est remonté par la trace : un candidat par valeur retrouvée.
         */
        private List<Candidate> candidates(Rule rule, Matcher matcher, int line) {
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
                Pattern separator = rule.listSeparator() != null ? rule.listSeparator() : LIST_SEPARATOR;
                for (String item : separator.split(list)) {
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
                primary = resolveArgument(matcher);
                if (primary == null) {
                    String argument = ProjectCode.argumentAt(text.content(), matcher.start("algo"));
                    // Une valeur tracée absente du catalogue ("some-algorithm" passé par un test) n'est pas un
                    // algorithme : sans valeur reconnue, l'appel reste non résolu.
                    List<Candidate> traced = trace(argument == null ? group(matcher, "algo") : argument, line).stream()
                            .map(t -> new Candidate(withParameters(mapped(rule, t.value()), rule, matcher),
                                    Provenance.of(t)))
                            .filter(c -> assetFactory.normalizer().normalize(c.raw()).isRecognized())
                            .toList();
                    return traced.isEmpty() ? List.of(new Candidate(null)) : traced;
                }
            }
            return List.of(new Candidate(withParameters(mapped(rule, primary), rule, matcher)));
        }

        private List<ValueTracer.Traced> trace(String expression, int line) {
            if (tracer == null || expression == null) {
                return List.of();
            }
            return tracer.get().trace(expression, file.path(), line);
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
                String value = "algo".equals(name) ? resolveArgument(matcher) : group(matcher, name);
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
         * Résout l'argument {@code algo} ; si c'est un identifiant non résolu dont le dernier segment est lui-même
         * un nom d'algorithme (ex. {@code Algorithms.AES_GCM}, {@code KeyProperties.KEY_ALGORITHM_RSA}), on le
         * retient. Pas pour un appel : {@code getDescription()} n'est pas l'algorithme "DES".
         */
        private String resolveArgument(Matcher matcher) {
            String expression = group(matcher, "algo");
            if (expression == null) {
                return null;
            }
            Optional<String> resolved = resolver.resolve(expression, text.content());
            if (resolved.isPresent()) {
                return resolved.get();
            }
            int after = matcher.end("algo");
            while (after < text.content().length() && Character.isWhitespace(text.content().charAt(after))) {
                after++;
            }
            boolean call = after < text.content().length() && text.content().charAt(after) == '(';
            if (!ConstantResolver.isLiteral(expression) && !call) {
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

        /**
         * Taille littérale, portée par une variable ou une constante numérique du fichier, ou remontée par la
         * trace (paramètre, champ). Si une condition donne plusieurs tailles, la plus faible est retenue : c'est
         * elle qui porte le risque.
         */
        private Sized sizeOf(String raw, int line) {
            Integer literal = parseSize(raw);
            if (literal != null || raw == null) {
                return new Sized(literal, Provenance.NONE);
            }
            Optional<Integer> constant = resolver.resolveNumber(raw, text.content()).filter(size -> size > 0);
            if (constant.isPresent()) {
                return new Sized(constant.get(), Provenance.NONE);
            }
            return trace(raw, line).stream()
                    .filter(t -> parseSize(t.value()) != null)
                    .min(Comparator.comparing(t -> parseSize(t.value())))
                    .map(t -> new Sized(parseSize(t.value()), Provenance.of(t)))
                    .orElse(new Sized(null, Provenance.NONE));
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

    /**
     * @param raw    nom brut, null si l'argument n'est pas résolu
     * @param provenance trajets de la valeur quand elle vient d'ailleurs
     */
    private record Candidate(String raw, Provenance provenance) {

        Candidate(String raw) {
            this(raw, Provenance.NONE);
        }
    }

    /**
     * Paquet fournissant les motifs de déclaration et les commentaires du langage : un paquet transverse (ex. JWT)
     * réutilise ceux du paquet principal du langage ; un langage qui emprunte les règles d'un autre (VB.NET et
     * F# celles de C#, Erlang celles d'Elixir) garde sa syntaxe, décrite par un paquet qui lui est propre.
     */
    private RulePack scopePackFor(Language language, RulePack current) {
        Optional<RulePack> dedicated = packs.stream()
                .filter(p -> p.languages().equals(Set.of(language)) && !p.functionPatterns().isEmpty())
                .findFirst();
        if (!current.functionPatterns().isEmpty()) {
            return dedicated.filter(d -> !current.languages().equals(Set.of(language))).orElse(current);
        }
        return packs.stream()
                .filter(p -> p.appliesTo(language) && !p.functionPatterns().isEmpty())
                .findFirst()
                .orElse(current);
    }

    private static String keyType(String declared, AlgorithmSpec spec) {
        if (!AUTO_KEY.equals(declared)) {
            return declared;
        }
        if (!spec.isRecognized()) {
            return AssetFactory.UNIDENTIFIED_KEY;
        }
        return SYMMETRIC_KEY_PRIMITIVES.contains(spec.primitive()) ? SECRET_KEY : PRIVATE_KEY;
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
