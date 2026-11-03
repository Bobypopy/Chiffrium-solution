package com.chiffrium.infrastructure.cdxgen;

import com.chiffrium.application.port.CbomWriter;
import com.chiffrium.application.port.SbomGenerator.SbomResult;
import com.chiffrium.domain.model.AlgorithmSpec;
import com.chiffrium.domain.model.AssetType;
import com.chiffrium.domain.model.CryptoAsset;
import com.chiffrium.domain.model.CryptoFunction;
import com.chiffrium.domain.model.DetectionSource;
import com.chiffrium.domain.model.Library;
import com.chiffrium.domain.model.MaterialInfo;
import com.chiffrium.domain.model.Occurrence;
import com.chiffrium.domain.model.PolicyVerdict;
import com.chiffrium.domain.model.SourceInfo;
import com.chiffrium.domain.model.Vulnerability;
import com.chiffrium.infrastructure.json.JsonNodes;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * Assemble le CBOM final (CycloneDX 1.6) :
 * <ul>
 *   <li>composants "library/framework" repris intégralement des SBOM cdxgen (licences, hashes, évidences) ;</li>
 *   <li>actifs cryptographiques évalués, au format cryptoProperties 1.6, avec leurs occurrences ;</li>
 *   <li>vulnérabilités OSV au format CycloneDX "vulnerabilities" ;</li>
 *   <li>verdict de politique en propriétés "chiffrium:*" (extension non normative).</li>
 * </ul>
 */
public final class CycloneDxCbomWriter implements CbomWriter {

    private static final Logger LOG = LoggerFactory.getLogger(CycloneDxCbomWriter.class);
    private static final String SPEC_VERSION = "1.6";
    private static final String PROPERTY_PREFIX = "chiffrium:";
    private static final Set<String> CDX_MODES = Set.of("cbc", "ecb", "ccm", "gcm", "cfb", "ofb", "ctr");
    private static final Map<String, String> CDX_PADDINGS = Map.of(
            "PKCS7", "pkcs7", "PKCS1-v1.5", "pkcs1v15", "OAEP", "oaep", "NoPadding", "raw");
    /** CycloneDX : niveau 0 = cassable par un ordinateur quantique. */
    private static final int QUANTUM_VULNERABLE_LEVEL = 0;
    private static final String OTHER = "other";

    private final ObjectMapper mapper;
    private final Clock clock;
    private final String toolVersion;

    public CycloneDxCbomWriter(ObjectMapper mapper, Clock clock, String toolVersion) {
        this.mapper = mapper;
        this.clock = clock;
        this.toolVersion = toolVersion;
    }

    @Override
    public void write(Path target, SbomResult sbom, SourceInfo source, List<CryptoAsset> assets,
                      List<Library> libraries) {
        ObjectNode bom = mapper.createObjectNode();
        bom.put("bomFormat", "CycloneDX");
        bom.put("specVersion", SPEC_VERSION);
        bom.put("serialNumber", "urn:uuid:" + UUID.randomUUID());
        bom.put("version", 1);
        String rootRef = "application:" + applicationName(source);
        bom.set("metadata", metadata(source, rootRef));

        Map<String, JsonNode> components = new LinkedHashMap<>();
        Map<String, Set<String>> dependencies = new LinkedHashMap<>();
        for (Path file : sbom.boms()) {
            mergeSbom(file, components, dependencies);
        }
        ArrayNode componentArray = bom.putArray("components");
        components.values().forEach(componentArray::add);
        assets.forEach(asset -> componentArray.add(toComponent(asset)));

        dependencies.computeIfAbsent(rootRef, k -> new LinkedHashSet<>())
                .addAll(assets.stream().map(CryptoAsset::bomRef).toList());
        ArrayNode dependencyArray = bom.putArray("dependencies");
        dependencies.forEach((ref, dependsOn) -> {
            ObjectNode dependency = dependencyArray.addObject();
            dependency.put("ref", ref);
            ArrayNode refs = dependency.putArray("dependsOn");
            dependsOn.forEach(refs::add);
        });

        ArrayNode vulnerabilities = vulnerabilities(libraries);
        if (!vulnerabilities.isEmpty()) {
            bom.set("vulnerabilities", vulnerabilities);
        }
        try {
            Files.createDirectories(target.getParent());
            mapper.writerWithDefaultPrettyPrinter().writeValue(target.toFile(), bom);
        } catch (IOException e) {
            throw new UncheckedIOException("Écriture du CBOM impossible : " + target, e);
        }
    }

    private ObjectNode metadata(SourceInfo source, String rootRef) {
        ObjectNode metadata = mapper.createObjectNode();
        metadata.put("timestamp", clock.instant().toString());
        ArrayNode tools = metadata.putObject("tools").putArray("components");
        ObjectNode tool = tools.addObject();
        tool.put("type", "application");
        tool.put("name", "chiffrium");
        tool.put("version", toolVersion);

        ObjectNode component = metadata.putObject("component");
        component.put("type", "application");
        component.put("bom-ref", rootRef);
        component.put("name", applicationName(source));
        ArrayNode properties = component.putArray("properties");
        addProperty(properties, "source:target", source.target());
        addProperty(properties, "source:kind", source.kind());
        addProperty(properties, "source:branch", source.branch());
        addProperty(properties, "source:commit", source.commit());
        addProperty(properties, "source:languages", source.languages().stream()
                .map(l -> l.id()).sorted().collect(Collectors.joining(",")));
        return metadata;
    }

    private void mergeSbom(Path file, Map<String, JsonNode> components, Map<String, Set<String>> dependencies) {
        try {
            JsonNode root = mapper.readTree(file.toFile());
            JsonNodes.array(root, "components")
                    .filter(c -> !"cryptographic-asset".equals(JsonNodes.text(c, "type")))
                    .forEach(c -> components.putIfAbsent(
                            JsonNodes.text(c, "bom-ref") != null ? JsonNodes.text(c, "bom-ref") : UUID.randomUUID().toString(), c));
            JsonNodes.array(root, "dependencies").forEach(d -> {
                String ref = JsonNodes.text(d, "ref");
                if (ref != null) {
                    dependencies.computeIfAbsent(ref, k -> new LinkedHashSet<>()).addAll(JsonNodes.texts(d, "dependsOn"));
                }
            });
        } catch (IOException e) {
            LOG.warn("SBOM ignoré lors de l'assemblage du CBOM : {}", file, e);
        }
    }

    ObjectNode toComponent(CryptoAsset asset) {
        ObjectNode component = mapper.createObjectNode();
        component.put("type", "cryptographic-asset");
        component.put("bom-ref", asset.bomRef());
        component.put("name", asset.name());
        if (asset.description() != null) {
            component.put("description", asset.description());
        }
        ObjectNode crypto = component.putObject("cryptoProperties");
        crypto.put("assetType", asset.assetType().cycloneDxValue());
        AlgorithmSpec spec = asset.algorithm();
        switch (asset.assetType()) {
            case ALGORITHM -> crypto.set("algorithmProperties", algorithmProperties(asset));
            case PROTOCOL -> crypto.set("protocolProperties", protocolProperties(spec));
            case CERTIFICATE -> crypto.set("certificateProperties", certificateProperties(asset.material(), spec));
            case RELATED_CRYPTO_MATERIAL -> crypto.set("relatedCryptoMaterialProperties",
                    materialProperties(asset.material(), spec));
        }
        if (spec != null && spec.oid() != null && asset.assetType() == AssetType.ALGORITHM) {
            crypto.put("oid", spec.oid());
        }
        if (!asset.occurrences().isEmpty()) {
            ArrayNode occurrences = component.putObject("evidence").putArray("occurrences");
            asset.occurrences().forEach(o -> occurrences.add(occurrence(o)));
        }
        component.set("properties", policyProperties(asset));
        return component;
    }

    private ObjectNode algorithmProperties(CryptoAsset asset) {
        AlgorithmSpec spec = asset.algorithm();
        ObjectNode props = mapper.createObjectNode();
        props.put("primitive", spec.primitive().cycloneDxValue());
        if (spec.keySize() != null) {
            props.put("parameterSetIdentifier", String.valueOf(spec.keySize()));
        }
        if (spec.curve() != null) {
            props.put("curve", spec.curve());
        }
        if (spec.mode() != null) {
            String mode = spec.mode().toLowerCase(Locale.ROOT);
            props.put("mode", CDX_MODES.contains(mode) ? mode : OTHER);
        }
        if (spec.padding() != null) {
            props.put("padding", CDX_PADDINGS.getOrDefault(spec.padding(), OTHER));
        }
        props.put("executionEnvironment", "software-plain-ram");
        if (!asset.functions().isEmpty()) {
            ArrayNode functions = props.putArray("cryptoFunctions");
            asset.functions().stream().map(CryptoFunction::cycloneDxValue).sorted().forEach(functions::add);
        }
        if (asset.verdict() != null && asset.verdict().quantumVulnerable()) {
            props.put("nistQuantumSecurityLevel", QUANTUM_VULNERABLE_LEVEL);
        }
        return props;
    }

    private ObjectNode protocolProperties(AlgorithmSpec spec) {
        ObjectNode props = mapper.createObjectNode();
        String name = spec == null || spec.family() == null ? "" : spec.family();
        props.put("type", name.toUpperCase(Locale.ROOT).startsWith("TLS") || name.toUpperCase(Locale.ROOT).startsWith("SSL")
                ? "tls" : OTHER);
        String version = name.replaceAll("[^0-9.]", "");
        if (!version.isEmpty()) {
            props.put("version", version);
        }
        return props;
    }

    private ObjectNode certificateProperties(MaterialInfo material, AlgorithmSpec spec) {
        ObjectNode props = mapper.createObjectNode();
        if (material != null) {
            putIfPresent(props, "subjectName", material.subject());
            putIfPresent(props, "issuerName", material.issuer());
            putIfPresent(props, "notValidBefore", material.notValidBefore());
            putIfPresent(props, "notValidAfter", material.notValidAfter());
            putIfPresent(props, "certificateFormat", "X.509");
            putIfPresent(props, "certificateExtension", material.format());
        }
        return props;
    }

    private ObjectNode materialProperties(MaterialInfo material, AlgorithmSpec spec) {
        ObjectNode props = mapper.createObjectNode();
        String type = material == null ? "unknown" : material.materialType();
        props.put("type", "keystore".equals(type) ? OTHER : type);
        if (material != null) {
            putIfPresent(props, "format", material.format());
        }
        if (spec != null && spec.keySize() != null) {
            props.put("size", spec.keySize());
        }
        return props;
    }

    private ObjectNode occurrence(Occurrence occurrence) {
        ObjectNode node = mapper.createObjectNode();
        node.put("location", occurrence.file());
        if (occurrence.line() != null) {
            node.put("line", occurrence.line());
        }
        if (occurrence.column() != null) {
            node.put("offset", occurrence.column());
        }
        if (occurrence.snippet() != null) {
            node.put("additionalContext", occurrence.snippet());
        }
        return node;
    }

    private ArrayNode policyProperties(CryptoAsset asset) {
        ArrayNode properties = mapper.createArrayNode();
        addProperty(properties, "detection:sources", asset.sources().stream()
                .map(DetectionSource::id).sorted().collect(Collectors.joining(",")));
        PolicyVerdict verdict = asset.verdict();
        if (verdict != null) {
            addProperty(properties, "policy:status", verdict.status().id());
            addProperty(properties, "policy:severity", verdict.severity().id());
            addProperty(properties, "policy:quantumVulnerable", String.valueOf(verdict.quantumVulnerable()));
            if (verdict.validUntil() != null) {
                addProperty(properties, "policy:validUntil", String.valueOf(verdict.validUntil()));
            }
            verdict.reasons().forEach(reason -> addProperty(properties, "policy:reason", reason));
            addProperty(properties, "policy:recommendation", verdict.recommendation());
        }
        return properties;
    }

    private ArrayNode vulnerabilities(List<Library> libraries) {
        ArrayNode array = mapper.createArrayNode();
        Map<String, ObjectNode> byId = new LinkedHashMap<>();
        for (Library library : libraries) {
            for (Vulnerability vulnerability : library.vulnerabilities()) {
                ObjectNode node = byId.computeIfAbsent(vulnerability.id(), id -> {
                    ObjectNode v = mapper.createObjectNode();
                    v.put("id", id);
                    v.putObject("source").put("name", "OSV").put("url", vulnerability.url());
                    putIfPresent(v, "description", vulnerability.summary());
                    if (vulnerability.severity() != null) {
                        v.putArray("ratings").addObject().put("severity", cdxSeverity(vulnerability.severity()));
                    }
                    v.putArray("affects");
                    return v;
                });
                String ref = library.bomRef() != null ? library.bomRef() : library.purl();
                ((ArrayNode) node.get("affects")).addObject().put("ref", ref);
            }
        }
        byId.values().forEach(array::add);
        return array;
    }

    private static String cdxSeverity(String severity) {
        String lower = severity.toLowerCase(Locale.ROOT);
        return switch (lower) {
            case "critical", "high", "medium", "low" -> lower;
            case "moderate" -> "medium";
            default -> "unknown";
        };
    }

    private static String applicationName(SourceInfo source) {
        String target = source.target() == null ? "application" : source.target().replaceAll("[/\\\\]+$", "");
        String last = target.substring(Math.max(target.lastIndexOf('/'), target.lastIndexOf('\\')) + 1);
        return last.endsWith(".git") ? last.substring(0, last.length() - ".git".length()) : last;
    }

    private static void addProperty(ArrayNode properties, String name, String value) {
        if (value != null && !value.isBlank()) {
            properties.addObject().put("name", PROPERTY_PREFIX + name).put("value", value);
        }
    }

    private static void putIfPresent(ObjectNode node, String field, String value) {
        if (value != null && !value.isBlank()) {
            node.put(field, value);
        }
    }
}
