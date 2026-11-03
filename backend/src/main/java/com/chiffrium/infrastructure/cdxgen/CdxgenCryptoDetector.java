package com.chiffrium.infrastructure.cdxgen;

import com.chiffrium.application.port.CryptoDetector;
import com.chiffrium.domain.asset.AssetFactory;
import com.chiffrium.domain.asset.CryptoFunctionHints;
import com.chiffrium.domain.model.AlgorithmSpec;
import com.chiffrium.domain.model.CryptoAsset;
import com.chiffrium.domain.model.CryptoFunction;
import com.chiffrium.domain.model.DetectionSource;
import com.chiffrium.domain.model.Language;
import com.chiffrium.domain.model.Occurrence;
import com.chiffrium.domain.policy.AlgorithmDefinition;
import com.chiffrium.infrastructure.json.JsonNodes;
import com.chiffrium.infrastructure.scan.FileClassifier;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * Exploite les sorties cdxgen :
 * <ol>
 *   <li><b>slices reachables</b> : chaque flux contenant un littéral taggé "crypto-algorithm" donne une
 *       occurrence localisée (fichier, ligne, colonne, méthode). Le tag "crypto-generate" et les noms
 *       d'appels du flux indiquent l'opération (génération de clé, chiffrement...) ;</li>
 *   <li><b>composants cryptographic-asset</b> du CBOM : ajoutés s'ils n'ont pas déjà été localisés par un flux
 *       (cdxgen ne fournit ni fichier ni ligne pour ces composants).</li>
 * </ol>
 * L'ancienne version corrélait les actifs aux usages par recherche de sous-chaînes (ex. "des" trouvé
 * dans "deserialize") ; ce n'est plus le cas : seuls les flux taggés par atom sont retenus.
 */
public final class CdxgenCryptoDetector implements CryptoDetector {

    private static final Logger LOG = LoggerFactory.getLogger(CdxgenCryptoDetector.class);
    private static final String TAG_ALGORITHM = "crypto-algorithm";
    private static final String TAG_GENERATE = "crypto-generate";
    private static final String CRYPTO_ASSET_TYPE = "cryptographic-asset";
    private static final String UNKNOWN_FILE = "<unknown>";
    private static final int MAX_SNIPPET_LENGTH = 200;

    private final AssetFactory assetFactory;
    private final ObjectMapper mapper;

    public CdxgenCryptoDetector(AssetFactory assetFactory, ObjectMapper mapper) {
        this.assetFactory = assetFactory;
        this.mapper = mapper;
    }

    @Override
    public String name() {
        return "cdxgen";
    }

    @Override
    public DetectionResult detect(DetectionContext context) {
        List<CryptoAsset> assets = new ArrayList<>();
        List<String> warnings = new ArrayList<>();
        for (Map.Entry<Language, Path> slice : context.sbom().reachablesSlices().entrySet()) {
            readTree(slice.getValue(), warnings)
                    .ifPresent(root -> assets.addAll(fromReachables(root, slice.getKey())));
        }
        Set<String> localizedFamilies = new HashSet<>();
        assets.forEach(a -> localizedFamilies.add(a.algorithm().catalogId()));
        for (Path bom : context.sbom().boms()) {
            readTree(bom, warnings).ifPresent(root -> JsonNodes.array(root, "components")
                    .filter(c -> CRYPTO_ASSET_TYPE.equals(JsonNodes.text(c, "type")))
                    .map(this::fromComponent)
                    .filter(a -> a.algorithm() == null || !localizedFamilies.contains(a.algorithm().catalogId())
                            || !a.occurrences().isEmpty())
                    .forEach(assets::add));
        }
        return new DetectionResult(assets, List.of(), warnings);
    }

    List<CryptoAsset> fromReachables(JsonNode root, Language language) {
        List<CryptoAsset> assets = new ArrayList<>();
        JsonNodes.array(root, "reachables").forEach(reachable -> {
            List<JsonNode> flows = JsonNodes.array(reachable, "flows").toList();
            Set<CryptoFunction> functions = functionsOf(flows);
            for (JsonNode flow : flows) {
                String tags = JsonNodes.text(flow, "tags");
                if (tags == null || !tags.contains(TAG_ALGORITHM)) {
                    continue;
                }
                String literal = Optional.ofNullable(JsonNodes.text(flow, "code")).orElse(JsonNodes.text(flow, "name"));
                AlgorithmSpec spec = assetFactory.normalizer().normalize(literal);
                if (!spec.isRecognized()) {
                    LOG.debug("Littéral crypto non reconnu ignoré : {}", literal);
                    continue;
                }
                Occurrence occurrence = occurrenceOf(flow, language, literal, functions);
                assets.add(assetFactory.fromSpec(spec, occurrence, functions, DetectionSource.CDXGEN, null));
            }
        });
        return assets;
    }

    CryptoAsset fromComponent(JsonNode component) {
        String name = JsonNodes.text(component, "name");
        JsonNode crypto = component.path("cryptoProperties");
        String oid = JsonNodes.text(crypto, "oid");
        AlgorithmSpec spec = assetFactory.normalizer().normalize(name);
        if (!spec.isRecognized() && oid != null) {
            spec = assetFactory.normalizer().byOid(oid)
                    .map(AlgorithmDefinition::name)
                    .map(assetFactory.normalizer()::normalize)
                    .orElse(spec);
        }
        JsonNode algorithmProperties = crypto.path("algorithmProperties");
        Integer parameterSet = parseInteger(JsonNodes.text(algorithmProperties, "parameterSetIdentifier"));
        if (spec.keySize() == null && parameterSet != null) {
            spec = spec.withKeySize(parameterSet);
        }
        Set<CryptoFunction> functions = EnumSet.noneOf(CryptoFunction.class);
        JsonNodes.texts(algorithmProperties, "cryptoFunctions").stream()
                .map(CryptoFunction::fromCycloneDx)
                .forEach(functions::add);

        List<Occurrence> occurrences = JsonNodes.array(component.path("evidence"), "occurrences")
                .map(o -> {
                    String file = normalizePath(JsonNodes.text(o, "location"));
                    return new Occurrence(file, JsonNodes.integer(o, "line"), JsonNodes.integer(o, "offset"), null,
                            truncate(JsonNodes.text(o, "additionalContext")), languageOf(file, null),
                            DetectionSource.CDXGEN, "cdxgen:evidence", functions);
                })
                .toList();

        CryptoAsset asset = assetFactory.fromSpec(spec, null, functions, DetectionSource.CDXGEN,
                JsonNodes.text(component, "description"));
        return occurrences.isEmpty() ? asset : new CryptoAsset(asset.bomRef(), asset.name(), asset.assetType(),
                asset.algorithm(), asset.material(), asset.description(), asset.functions(), asset.sources(),
                occurrences, null);
    }

    private static Set<CryptoFunction> functionsOf(List<JsonNode> flows) {
        Set<CryptoFunction> functions = EnumSet.noneOf(CryptoFunction.class);
        for (JsonNode flow : flows) {
            String tags = JsonNodes.text(flow, "tags");
            if (tags != null && tags.contains(TAG_GENERATE)) {
                functions.add(CryptoFunction.KEYGEN);
            }
            functions.addAll(CryptoFunctionHints.fromCallName(JsonNodes.text(flow, "name")));
        }
        return functions;
    }

    private static Occurrence occurrenceOf(JsonNode flow, Language sliceLanguage, String literal,
                                           Set<CryptoFunction> functions) {
        String file = normalizePath(JsonNodes.text(flow, "parentFileName"));
        String className = JsonNodes.text(flow, "parentClassName");
        String method = JsonNodes.text(flow, "parentMethodName");
        String function = method == null ? null : (className == null ? method : className + "." + method);
        return new Occurrence(file, JsonNodes.integer(flow, "lineNumber"), JsonNodes.integer(flow, "columnNumber"),
                function, truncate(literal), languageOf(file, sliceLanguage), DetectionSource.CDXGEN,
                "atom:" + TAG_ALGORITHM, functions);
    }

    private static Language languageOf(String file, Language fallback) {
        return file == null ? fallback : FileClassifier.languageOf(file).orElse(fallback);
    }

    static String normalizePath(String path) {
        if (path == null || UNKNOWN_FILE.equals(path)) {
            return null;
        }
        String normalized = path.replace('\\', '/');
        return normalized.startsWith("./") ? normalized.substring(2) : normalized;
    }

    private static String truncate(String value) {
        if (value == null) {
            return null;
        }
        return value.length() > MAX_SNIPPET_LENGTH ? value.substring(0, MAX_SNIPPET_LENGTH) + "..." : value;
    }

    private static Integer parseInteger(String value) {
        if (value == null || !value.chars().allMatch(Character::isDigit)) {
            return null;
        }
        try {
            return Integer.parseInt(value);
        } catch (NumberFormatException e) {
            return null;
        }
    }

    private Optional<JsonNode> readTree(Path file, List<String> warnings) {
        try {
            return Optional.of(mapper.readTree(file.toFile()));
        } catch (IOException e) {
            warnings.add("Fichier cdxgen illisible : " + file.getFileName() + " (" + e.getMessage() + ")");
            return Optional.empty();
        }
    }
}
