package com.chiffrium.domain.policy;

import com.chiffrium.domain.model.AlgorithmSpec;
import com.chiffrium.domain.model.Primitive;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.EnumMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Function;
import java.util.regex.Pattern;

/**
 * Transforme un nom d'algorithme brut, quelle que soit sa syntaxe (JCA, OpenSSL, Go, Python...),
 * en {@link AlgorithmSpec} canonique. Toute la connaissance vient du {@link AlgorithmCatalog} :
 * <ol>
 *   <li>le nom est compacté (minuscules, sans séparateur) et découpé en mots ;</li>
 *   <li>les alias d'algorithmes sont recherchés du plus long au plus court, chaque zone reconnue
 *       étant "consommée" pour éviter les doubles lectures (ex. "desede" avant "des") ;</li>
 *   <li>puis les courbes, modes et bourrages sur les zones restantes ;</li>
 *   <li>enfin une taille de clé plausible parmi les chiffres restants.</li>
 * </ol>
 * Classe sans état mutable, sûre en concurrence.
 */
public final class AlgorithmNormalizer {

    private static final int MIN_KEY_SIZE_BITS = 40;
    private static final int MAX_KEY_SIZE_BITS = 16_384;
    private static final int BITS_PER_BYTE = 8;
    private static final String SIGNATURE_JOINER = "with";
    /** Au-delà de cette longueur, un alias est assez distinctif pour être cherché n'importe où. */
    private static final int MAX_SHORT_ALIAS_LENGTH = 3;

    /** Priorité pour choisir l'algorithme principal d'un nom composite (plus petit = prioritaire). */
    private static final List<Primitive> PRIMARY_PRECEDENCE = List.of(
            Primitive.KEM, Primitive.SIGNATURE, Primitive.PUBLIC_KEY_ENCRYPTION, Primitive.KEY_AGREEMENT,
            Primitive.KDF, Primitive.AUTHENTICATED_ENCRYPTION, Primitive.BLOCK_CIPHER, Primitive.STREAM_CIPHER,
            Primitive.MAC, Primitive.DRBG, Primitive.XOF, Primitive.HASH, Primitive.COMBINER, Primitive.OTHER,
            Primitive.UNKNOWN);

    /** Les modes d'opération n'ont de sens que pour ces primitives ("RSA/ECB" en Java n'est pas de l'ECB). */
    private static final List<Primitive> MODE_BEARING_PRIMITIVES = List.of(
            Primitive.BLOCK_CIPHER, Primitive.AUTHENTICATED_ENCRYPTION);

    /** Algorithmes à clé publique dont le hachage s'écrit devant ("SHA256withRSA"), comme en Java. */
    private static final List<Primitive> SIGNATURE_STYLE = List.of(
            Primitive.SIGNATURE, Primitive.PUBLIC_KEY_ENCRYPTION, Primitive.OTHER);

    private static final Pattern PARENTHESIS = Pattern.compile("\\s*\\([^)]*\\)");

    private static final String GENERIC_EC_ID = "ec";
    /**
     * Schémas désignés par un niveau plutôt que par une taille en bits (ML-DSA-44/65/87) : un nombre de deux ou
     * trois chiffres collé au nom de l'algorithme est retenu même s'il n'est pas un multiple de 8.
     */
    private static final List<Primitive> PARAMETER_SET_PRIMITIVES = List.of(Primitive.SIGNATURE, Primitive.KEM);
    private static final int MIN_PARAMETER_SET_DIGITS = 2;
    private static final int MAX_PARAMETER_SET_DIGITS = 3;

    private final AlgorithmCatalog catalog;
    private final List<Alias<AlgorithmDefinition>> algorithmAliases;
    private final List<Alias<ParameterDefinition>> curveAliases;
    private final List<Alias<ParameterDefinition>> modeAliases;
    private final List<Alias<ParameterDefinition>> paddingAliases;
    private final Map<Primitive, Integer> precedence = new EnumMap<>(Primitive.class);

    public AlgorithmNormalizer(AlgorithmCatalog catalog) {
        this.catalog = catalog;
        this.algorithmAliases = index(catalog.algorithms(), AlgorithmDefinition::aliases, AlgorithmDefinition::tokens);
        this.curveAliases = index(catalog.curves(), ParameterDefinition::aliases, ParameterDefinition::tokens);
        this.modeAliases = index(catalog.modes(), ParameterDefinition::aliases, ParameterDefinition::tokens);
        this.paddingAliases = index(catalog.paddings(), ParameterDefinition::aliases, ParameterDefinition::tokens);
        for (int i = 0; i < PRIMARY_PRECEDENCE.size(); i++) {
            precedence.put(PRIMARY_PRECEDENCE.get(i), i);
        }
    }

    public AlgorithmCatalog catalog() {
        return catalog;
    }

    /**
     * Normalise un nom brut. Ne renvoie jamais null : un nom inconnu donne une spec non reconnue
     * ({@link AlgorithmSpec#isRecognized()} faux) qui conserve le nom d'origine.
     */
    public AlgorithmSpec normalize(String rawName) {
        String raw = rawName == null ? "" : stripQuotes(rawName.trim());
        Text text = Text.of(raw);

        List<Hit<AlgorithmDefinition>> algorithms = text.find(algorithmAliases);
        List<Hit<ParameterDefinition>> curves = text.find(curveAliases);
        List<Hit<ParameterDefinition>> modes = text.find(modeAliases);
        List<Hit<ParameterDefinition>> paddings = text.find(paddingAliases);
        Integer keySize = text.findKeySize();

        if (algorithms.isEmpty() && !curves.isEmpty()) {
            catalog.findAlgorithm(GENERIC_EC_ID).ifPresent(ec -> algorithms.add(new Hit<>(ec, 0, 0)));
        }
        if (algorithms.isEmpty()) {
            return new AlgorithmSpec(raw, null, raw.isEmpty() ? null : raw, List.of(), List.of(), Primitive.UNKNOWN,
                    null, null, keySize, first(curves), null);
        }

        AlgorithmDefinition primary = algorithms.stream()
                .map(Hit::definition)
                .min(Comparator.comparingInt(def -> precedence.getOrDefault(def.primitive(), Integer.MAX_VALUE)))
                .orElseThrow();
        List<AlgorithmDefinition> secondary = algorithms.stream()
                .sorted(Comparator.comparingInt(Hit::position))
                .map(Hit::definition)
                .filter(def -> !def.id().equals(primary.id()))
                .distinct()
                .toList();

        Primitive primitive = primary.primitive();
        if (isHashThenKeySignature(text, algorithms, primary)) {
            primitive = Primitive.SIGNATURE;
        }
        if (keySize == null && PARAMETER_SET_PRIMITIVES.contains(primitive)) {
            keySize = algorithms.stream()
                    .filter(hit -> hit.definition().id().equals(primary.id()))
                    .map(hit -> text.parameterSetAfter(hit.end()))
                    .filter(Objects::nonNull)
                    .findFirst()
                    .orElse(null);
        }
        String mode = MODE_BEARING_PRIMITIVES.contains(primitive) ? first(modes) : null;
        String padding = first(paddings);
        List<String> components = secondary.stream().map(AlgorithmDefinition::id).toList();
        String oid = primary.oidFor(keySize, idOf(catalog.findMode(mode)), idOf(catalog.findPadding(padding)),
                components, raw);

        return new AlgorithmSpec(
                raw,
                primary.id(),
                primary.name(),
                components,
                secondary.stream().map(AlgorithmDefinition::name).toList(),
                primitive,
                mode,
                padding,
                keySize,
                first(curves),
                oid);
    }

    private static String idOf(Optional<ParameterDefinition> parameter) {
        return parameter.map(ParameterDefinition::id).orElse(null);
    }

    /**
     * Détecte la convention "&lt;hash&gt;with&lt;clé&gt;" (SHA256withRSA, SHA384withECDSA) : un hachage
     * placé avant "with" et l'algorithme à clé publique placé après. "RSA/ECB/OAEPWithSHA-256..." n'en
     * fait pas partie car RSA précède "with".
     */
    private static boolean isHashThenKeySignature(Text text, List<Hit<AlgorithmDefinition>> hits,
                                                  AlgorithmDefinition primary) {
        int joiner = text.compact.indexOf(SIGNATURE_JOINER);
        boolean publicKeyPrimary = primary.primitive() == Primitive.PUBLIC_KEY_ENCRYPTION
                || primary.primitive() == Primitive.OTHER
                || primary.primitive() == Primitive.SIGNATURE;
        if (joiner < 0 || !publicKeyPrimary) {
            return false;
        }
        boolean hashBefore = hits.stream()
                .anyMatch(h -> h.definition().primitive() == Primitive.HASH && h.position() < joiner);
        boolean keyAfter = hits.stream()
                .anyMatch(h -> h.definition().id().equals(primary.id()) && h.position() > joiner);
        return hashBefore && keyAfter;
    }

    /**
     * Spec désignée par un OID (cdxgen fournit parfois l'OID avec un nom ambigu) : l'algorithme et, si l'OID est
     * réservé à un usage, sa taille, son mode, son bourrage et l'algorithme associé
     * (2.16.840.1.101.3.4.1.46 donne AES-256-GCM, 1.2.840.113549.1.1.11 SHA-256withRSA).
     */
    public Optional<AlgorithmSpec> fromOid(String oid) {
        return catalog.findByOid(oid).map(definition -> normalize(definition.oids().stream()
                .filter(ref -> ref.oid().equals(oid.trim()))
                .findFirst()
                .map(ref -> nameOf(definition, ref))
                .orElse(definition.name())));
    }

    /** Nom écrit comme dans le code ("SHA-256withRSA", "AES-256/GCM"), relu ensuite par {@link #normalize}. */
    private String nameOf(AlgorithmDefinition definition, AlgorithmDefinition.OidRef ref) {
        // Sans sa précision entre parenthèses ("GOST 28147-89 (Magma)") et, pour une entrée qui regroupe des
        // variantes ("RIPEMD-128 / RIPEMD-256"), la seule que l'OID désigne : sinon le nom les nommerait toutes.
        String name = PARENTHESIS.matcher(definition.name()).replaceAll("").trim();
        if (ref.variant() != null) {
            name = Arrays.stream(name.split("\\s+/\\s+"))
                    .filter(part -> Text.of(part).compact.contains(ref.variant()))
                    .findFirst()
                    .orElse(name);
        }
        String component = ref.component() == null ? null
                : catalog.findAlgorithm(ref.component()).map(AlgorithmDefinition::name).orElse(null);
        if (component != null) {
            name = SIGNATURE_STYLE.contains(definition.primitive()) ? component + "with" + name
                    : name + "-" + component;
        }
        if (ref.variant() != null) {
            name += "-" + ref.variant();
        }
        if (ref.keySize() != null) {
            name += "-" + ref.keySize();
        }
        for (Optional<ParameterDefinition> parameter : List.of(catalog.findMode(ref.mode()),
                catalog.findPadding(ref.padding()))) {
            name += parameter.map(p -> "/" + p.name()).orElse("");
        }
        return name;
    }

    private static String first(List<Hit<ParameterDefinition>> hits) {
        return hits.stream()
                .min(Comparator.comparingInt(Hit::position))
                .map(hit -> hit.definition().name())
                .orElse(null);
    }

    private static String stripQuotes(String value) {
        String result = value;
        while (result.length() >= 2 && isQuote(result.charAt(0)) && isQuote(result.charAt(result.length() - 1))) {
            result = result.substring(1, result.length() - 1).trim();
        }
        return result;
    }

    private static boolean isQuote(char c) {
        return c == '"' || c == '\'' || c == '`';
    }

    private static <T> List<Alias<T>> index(List<T> definitions,
                                            Function<T, List<String>> aliases,
                                            Function<T, List<String>> tokens) {
        List<Alias<T>> index = new ArrayList<>();
        for (T definition : definitions) {
            aliases.apply(definition).forEach(a -> index.add(new Alias<>(a, false, definition)));
            tokens.apply(definition).forEach(t -> index.add(new Alias<>(t, true, definition)));
        }
        // Les plus longs d'abord : "sha512256" doit gagner sur "sha512", "desede" sur "des".
        index.sort(Comparator.comparingInt((Alias<T> a) -> a.value().length()).reversed());
        return index;
    }

    private record Alias<T>(String value, boolean wholeTokenOnly, T definition) {
    }

    /** @param end fin (exclue) de la zone reconnue dans le nom compacté */
    private record Hit<T>(T definition, int position, int end) {
    }

    /**
     * Nom compacté avec suivi des zones déjà reconnues.
     */
    private static final class Text {
        private final String compact;
        private final boolean[] consumed;
        private final List<int[]> tokenBounds;

        private final String raw;
        private final int[] rawIndex;

        private Text(String raw, String compact, int[] rawIndex, List<int[]> tokenBounds) {
            this.raw = raw;
            this.compact = compact;
            this.rawIndex = rawIndex;
            this.consumed = new boolean[compact.length()];
            this.tokenBounds = tokenBounds;
        }

        static Text of(String raw) {
            String lower = raw.toLowerCase(Locale.ROOT);
            StringBuilder compact = new StringBuilder();
            List<Integer> positions = new ArrayList<>();
            List<int[]> bounds = new ArrayList<>();
            int tokenStart = -1;
            for (int i = 0; i < lower.length(); i++) {
                char c = lower.charAt(i);
                if (Character.isLetterOrDigit(c) && c < Byte.MAX_VALUE) {
                    if (tokenStart < 0) {
                        tokenStart = compact.length();
                    }
                    compact.append(c);
                    positions.add(i);
                } else if (tokenStart >= 0) {
                    bounds.add(new int[]{tokenStart, compact.length()});
                    tokenStart = -1;
                }
            }
            if (tokenStart >= 0) {
                bounds.add(new int[]{tokenStart, compact.length()});
            }
            int[] rawIndex = positions.stream().mapToInt(Integer::intValue).toArray();
            return new Text(raw, compact.toString(), rawIndex, bounds);
        }

        /**
         * Un alias court ("des", "aes", "rsa"...) doit former un mot : il ne peut pas commencer ou finir
         * au milieu d'un mot en minuscules. "deserialize" n'est donc pas du DES, alors que "AESGCM",
         * "PBEWithMD5AndDES", "aes256" ou "hashlib.md5" restent reconnus.
         */
        private boolean isWordLike(int start, int end) {
            return isBoundary(rawIndex[start], true) && isBoundary(rawIndex[end - 1], false);
        }

        private boolean isBoundary(int rawPosition, boolean atStart) {
            int outside = atStart ? rawPosition - 1 : rawPosition + 1;
            if (outside < 0 || outside >= raw.length()) {
                return true;
            }
            char inner = raw.charAt(rawPosition);
            char neighbour = raw.charAt(outside);
            if (!Character.isLetterOrDigit(neighbour) || Character.isDigit(inner) != Character.isDigit(neighbour)) {
                return true;
            }
            if (Character.isUpperCase(inner) && Character.isUpperCase(neighbour)) {
                return true;
            }
            // Transition camelCase : minuscule puis majuscule.
            return atStart ? Character.isLowerCase(neighbour) && Character.isUpperCase(inner)
                    : Character.isLowerCase(inner) && Character.isUpperCase(neighbour);
        }

        <T> List<Hit<T>> find(List<Alias<T>> aliases) {
            List<Hit<T>> hits = new ArrayList<>();
            for (Alias<T> alias : aliases) {
                if (alias.wholeTokenOnly()) {
                    for (int[] bound : tokenBounds) {
                        if (compact.substring(bound[0], bound[1]).equals(alias.value()) && isFree(bound[0], bound[1])) {
                            consume(bound[0], bound[1]);
                            hits.add(new Hit<>(alias.definition(), bound[0], bound[1]));
                        }
                    }
                    continue;
                }
                int from = 0;
                int index;
                while ((index = compact.indexOf(alias.value(), from)) >= 0) {
                    int end = index + alias.value().length();
                    boolean shortAlias = alias.value().length() <= MAX_SHORT_ALIAS_LENGTH;
                    if (isFree(index, end) && (!shortAlias || isWordLike(index, end))) {
                        consume(index, end);
                        hits.add(new Hit<>(alias.definition(), index, end));
                    }
                    from = index + 1;
                }
            }
            return hits;
        }

        Integer findKeySize() {
            int i = 0;
            while (i < compact.length()) {
                if (!consumed[i] && Character.isDigit(compact.charAt(i))) {
                    int end = i;
                    while (end < compact.length() && !consumed[end] && Character.isDigit(compact.charAt(end))) {
                        end++;
                    }
                    boolean detachedFromLetters = i == 0 || consumed[i - 1] || !Character.isLetter(compact.charAt(i - 1));
                    Integer size = parsePlausibleKeySize(compact.substring(i, end));
                    if (size != null && detachedFromLetters) {
                        return size;
                    }
                    i = end;
                } else {
                    i++;
                }
            }
            return null;
        }

        /** Niveau (deux ou trois chiffres libres) placé juste après la zone se terminant en {@code end}. */
        Integer parameterSetAfter(int end) {
            int stop = end;
            while (stop < compact.length() && !consumed[stop] && Character.isDigit(compact.charAt(stop))) {
                stop++;
            }
            int digits = stop - end;
            return digits >= MIN_PARAMETER_SET_DIGITS && digits <= MAX_PARAMETER_SET_DIGITS
                    ? Integer.valueOf(compact.substring(end, stop)) : null;
        }

        private static Integer parsePlausibleKeySize(String digits) {
            if (digits.length() > String.valueOf(MAX_KEY_SIZE_BITS).length()) {
                return null;
            }
            int value = Integer.parseInt(digits);
            boolean plausible = value >= MIN_KEY_SIZE_BITS && value <= MAX_KEY_SIZE_BITS && value % BITS_PER_BYTE == 0;
            return plausible ? value : null;
        }

        private boolean isFree(int start, int end) {
            for (int i = start; i < end; i++) {
                if (consumed[i]) {
                    return false;
                }
            }
            return true;
        }

        private void consume(int start, int end) {
            for (int i = start; i < end; i++) {
                consumed[i] = true;
            }
        }
    }
}
