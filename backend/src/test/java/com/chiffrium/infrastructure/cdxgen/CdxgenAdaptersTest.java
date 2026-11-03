package com.chiffrium.infrastructure.cdxgen;

import com.chiffrium.TestSupport;
import com.chiffrium.infrastructure.licenses.LicensePolicyLoader;
import com.chiffrium.application.port.CallEdgeExtractor.CallEdge;
import com.chiffrium.application.port.CryptoDetector.DetectionContext;
import com.chiffrium.application.port.ProjectScanner.ScanResult;
import com.chiffrium.application.port.SbomGenerator.SbomResult;
import com.chiffrium.domain.asset.AssetMerger;
import com.chiffrium.domain.model.CryptoAsset;
import com.chiffrium.domain.model.CryptoFunction;
import com.chiffrium.domain.model.DetectionSource;
import com.chiffrium.domain.model.Language;
import com.chiffrium.domain.model.Library;
import com.chiffrium.domain.model.Occurrence;
import com.chiffrium.domain.model.SourceInfo;
import com.chiffrium.domain.model.Vulnerability;
import com.chiffrium.domain.policy.PolicyEvaluator;
import com.fasterxml.jackson.databind.JsonNode;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests sur de vraies sorties de cdxgen 11.7 (projet crypto-package, fichiers copiés de output/Base74).
 */
class CdxgenAdaptersTest {

    private static final SbomResult SBOM = new SbomResult(
            List.of(TestSupport.fixture("cdxgen/bom-java.json")),
            Map.of(Language.JAVA, TestSupport.fixture("cdxgen/java-usages.slices.json")),
            Map.of(Language.JAVA, TestSupport.fixture("cdxgen/java-reachables.slices.json")),
            List.of());

    private List<CryptoAsset> detect() {
        var detector = new CdxgenCryptoDetector(TestSupport.ASSETS, TestSupport.MAPPER);
        var context = new DetectionContext(Path.of("."), new ScanResult(List.of(), List.of(), 0), SBOM);
        return AssetMerger.merge(detector.detect(context).assets());
    }

    @Test
    void reachableFlowsGiveLocatedAssets() {
        List<CryptoAsset> assets = detect();
        Set<String> names = assets.stream().map(CryptoAsset::name).collect(Collectors.toSet());
        assertThat(names).contains("AES", "RSA");

        CryptoAsset aes = assets.stream().filter(a -> a.name().equals("AES")).findFirst().orElseThrow();
        assertThat(aes.sources()).containsExactly(DetectionSource.CDXGEN);
        assertThat(aes.occurrences()).isNotEmpty().allSatisfy(o -> {
            assertThat(o.file()).endsWith(".java");
            assertThat(o.line()).isPositive();
            assertThat(o.function()).contains(".");
        });
    }

    @Test
    void generateTagIsTranslatedToKeyGeneration() {
        assertThat(detect()).flatExtracting(CryptoAsset::functions).contains(CryptoFunction.KEYGEN);
    }

    @Test
    void cbomComponentsWithoutLocationAreKeptOnlyWhenNotAlreadyLocated() {
        List<CryptoAsset> assets = detect();
        // PBKDF2 et SHA-256 viennent du CBOM : cdxgen ne les localise pas.
        assertThat(assets).anySatisfy(a -> assertThat(a.algorithm().catalogId()).isEqualTo("pbkdf2"));
        long aesAssetsWithoutLocation = assets.stream()
                .filter(a -> "aes".equals(a.algorithm().catalogId()) && a.occurrences().isEmpty())
                .count();
        assertThat(aesAssetsWithoutLocation).isZero();
    }

    @Test
    void usageSlicesProduceCallEdgesIncludingInvokedCalls() {
        List<CallEdge> edges = new SliceCallEdgeExtractor(TestSupport.MAPPER).extract(SBOM);
        assertThat(edges).isNotEmpty();
        assertThat(edges).anySatisfy(e -> {
            assertThat(e.callee()).startsWith("javax.crypto.Cipher");
            assertThat(e.external()).isTrue();
        });
        assertThat(edges).anySatisfy(e -> assertThat(e.external()).isFalse());
    }

    @Test
    void libraryReaderFlagsCryptoLibraries() {
        assertThat(CycloneDxLibraryReader.isCryptoLibrary("pkg:maven/org.bouncycastle/bcprov-jdk18on@1.78")).isTrue();
        assertThat(CycloneDxLibraryReader.isCryptoLibrary("pkg:pypi/cryptography@42.0.0")).isTrue();
        assertThat(CycloneDxLibraryReader.isCryptoLibrary("pkg:pypi/liboqs-python@0.12.0")).isTrue();
        assertThat(CycloneDxLibraryReader.isCryptoLibrary("pkg:cargo/ml-kem@0.2.1")).isTrue();
        assertThat(CycloneDxLibraryReader.isCryptoLibrary("pkg:npm/lodash@4.17.21")).isFalse();
        assertThat(new CycloneDxLibraryReader(TestSupport.MAPPER, LicensePolicyLoader.loadBuiltIn(TestSupport.MAPPER)).read(SBOM)).isEmpty();
    }

    @Test
    void cbomWriterProducesCycloneDx16(@TempDir Path dir) throws Exception {
        PolicyEvaluator evaluator = new PolicyEvaluator(TestSupport.CATALOG, TestSupport.clockAt(2026));
        Occurrence occurrence = new Occurrence("src/A.java", 12, 5, "A.run", "Cipher.getInstance(\"AES/ECB/PKCS5Padding\")",
                Language.JAVA, DetectionSource.RULES, "java.jca.get-instance", Set.of(CryptoFunction.ENCRYPT));
        CryptoAsset ecb = evaluator.evaluate(TestSupport.ASSETS.fromAlgorithmName("AES/ECB/PKCS5Padding", occurrence,
                Set.of(CryptoFunction.ENCRYPT), DetectionSource.RULES, null));
        Library library = new Library("pkg:maven/org.bouncycastle/bcprov-jdk15on@1.60",
                "pkg:maven/org.bouncycastle/bcprov-jdk15on@1.60", "org.bouncycastle", "bcprov-jdk15on", "1.60",
                "required", true, List.of(new Vulnerability("GHSA-xxxx", "Test", "MODERATE", List.of("CVE-1"), "url")));
        SourceInfo source = new SourceInfo("https://example.org/demo.git", "git", "main", "abc", Set.of(Language.JAVA),
                List.of());

        Path target = dir.resolve("cbom.json");
        new CycloneDxCbomWriter(TestSupport.MAPPER, TestSupport.clockAt(2026), "test").write(target, SBOM, source,
                List.of(ecb), List.of(library));

        JsonNode bom = TestSupport.MAPPER.readTree(target.toFile());
        assertThat(bom.path("specVersion").asText()).isEqualTo("1.6");
        assertThat(bom.path("metadata").path("component").path("name").asText()).isEqualTo("demo");
        JsonNode component = findCrypto(bom, ecb.bomRef());
        assertThat(component.path("cryptoProperties").path("assetType").asText()).isEqualTo("algorithm");
        JsonNode props = component.path("cryptoProperties").path("algorithmProperties");
        assertThat(props.path("primitive").asText()).isEqualTo("block-cipher");
        assertThat(props.path("mode").asText()).isEqualTo("ecb");
        assertThat(props.path("padding").asText()).isEqualTo("pkcs7");
        assertThat(props.path("cryptoFunctions").get(0).asText()).isEqualTo("encrypt");
        JsonNode location = component.path("evidence").path("occurrences").get(0);
        assertThat(location.path("location").asText()).isEqualTo("src/A.java");
        assertThat(location.path("line").asInt()).isEqualTo(12);
        assertThat(component.path("properties").toString()).contains("chiffrium:policy:status", "disallowed");
        assertThat(bom.path("vulnerabilities").get(0).path("ratings").get(0).path("severity").asText())
                .isEqualTo("medium");
    }

    @Test
    void generatedKeyPointsToItsAlgorithmInTheCbom(@TempDir Path dir) throws Exception {
        Occurrence at = new Occurrence("src/Keys.java", 3, 9, "Keys.pair", "KeyPairGenerator.getInstance(\"RSA\")",
                Language.JAVA, DetectionSource.RULES, "java.jca.get-instance", Set.of(CryptoFunction.KEYGEN));
        CryptoAsset rsa = TestSupport.ASSETS.fromAlgorithmName("RSA", at, Set.of(CryptoFunction.KEYGEN),
                DetectionSource.RULES, null);
        CryptoAsset key = TestSupport.ASSETS.generatedKey("private-key", rsa.algorithm(), at);
        SourceInfo source = new SourceInfo("demo", "local", null, null, Set.of(Language.JAVA), List.of());

        Path target = dir.resolve("cbom.json");
        new CycloneDxCbomWriter(TestSupport.MAPPER, TestSupport.clockAt(2026), "test").write(target, SBOM, source,
                List.of(rsa, key), List.of());

        JsonNode props = findCrypto(TestSupport.MAPPER.readTree(target.toFile()), key.bomRef())
                .path("cryptoProperties").path("relatedCryptoMaterialProperties");
        assertThat(props.path("type").asText()).isEqualTo("private-key");
        assertThat(props.path("algorithmRef").asText()).isEqualTo(rsa.bomRef());
    }

    /** Le CBOM dit ce qui résiste au quantique : catégorie NIST 1 à 5, 0 pour ce que Shor casse. */
    @Test
    void cbomGivesSecurityLevelsAndTheExactOid(@TempDir Path dir) throws Exception {
        PolicyEvaluator evaluator = new PolicyEvaluator(TestSupport.CATALOG, TestSupport.clockAt(2026));
        Occurrence at = new Occurrence("src/K.java", 1, 1, null, null, Language.JAVA, DetectionSource.RULES,
                "java.jca.get-instance", Set.of());
        List<CryptoAsset> assets = List.of("ML-KEM-768", "AES-256-GCM", "RSA-2048", "SHA256withECDSA").stream()
                .map(name -> evaluator.evaluate(TestSupport.ASSETS.fromAlgorithmName(name, at, Set.of(),
                        DetectionSource.RULES, null)))
                .toList();
        SourceInfo source = new SourceInfo("demo", "local", null, null, Set.of(Language.JAVA), List.of());

        Path target = dir.resolve("cbom.json");
        new CycloneDxCbomWriter(TestSupport.MAPPER, TestSupport.clockAt(2026), "test").write(target, SBOM, source,
                assets, List.of());

        JsonNode bom = TestSupport.MAPPER.readTree(target.toFile());
        JsonNode mlKem = findCrypto(bom, assets.get(0).bomRef()).path("cryptoProperties");
        assertThat(mlKem.path("oid").asText()).isEqualTo("2.16.840.1.101.3.4.4.2");
        assertThat(mlKem.path("algorithmProperties").path("nistQuantumSecurityLevel").asInt()).isEqualTo(3);
        assertThat(mlKem.path("algorithmProperties").path("classicalSecurityLevel").asInt()).isEqualTo(192);
        JsonNode aes = findCrypto(bom, assets.get(1).bomRef()).path("cryptoProperties");
        assertThat(aes.path("oid").asText()).isEqualTo("2.16.840.1.101.3.4.1.46");
        assertThat(aes.path("algorithmProperties").path("nistQuantumSecurityLevel").asInt()).isEqualTo(5);
        JsonNode rsa = findCrypto(bom, assets.get(2).bomRef()).path("cryptoProperties").path("algorithmProperties");
        assertThat(rsa.path("nistQuantumSecurityLevel").asInt()).isZero();
        assertThat(rsa.path("classicalSecurityLevel").asInt()).isEqualTo(112);
        JsonNode ecdsa = findCrypto(bom, assets.get(3).bomRef()).path("cryptoProperties");
        assertThat(ecdsa.path("oid").asText()).isEqualTo("1.2.840.10045.4.3.2");
        assertThat(ecdsa.path("algorithmProperties").path("nistQuantumSecurityLevel").asInt()).isZero();
        assertThat(ecdsa.path("algorithmProperties").has("classicalSecurityLevel")).as("courbe inconnue").isFalse();
    }

    private static JsonNode findCrypto(JsonNode bom, String ref) {
        for (JsonNode component : bom.path("components")) {
            if (ref.equals(component.path("bom-ref").asText())) {
                return component;
            }
        }
        throw new AssertionError("Composant absent : " + ref);
    }

    @Test
    void invocationUsesExplicitSlicePathsAndDisablesInstall(@TempDir Path out) {
        var invocation = new CdxgenSbomGenerator.Invocation("java", out, true);
        List<String> command = invocation.command("cdxgen", false, Path.of("/src"));
        assertThat(command).containsSequence("-t", "java")
                .contains("--include-crypto", "--no-install-deps", "--usages-slices-file",
                        out.resolve("java-usages.slices.json").toString())
                .containsSequence("--exclude-type", "maven")
                .containsSequence("--exclude-type", "gradle")
                .endsWith(Path.of("/src").toString());
        assertThat(invocation.command("cdxgen", true, Path.of("/src")))
                .doesNotContain("--no-install-deps", "--exclude-type");
        assertThat(CdxgenSbomGenerator.allowedCommands(null)).isEqualTo("atom,node,go,jar");
        assertThat(CdxgenSbomGenerator.allowedCommands("/opt/atom/bin/atom --flag"))
                .isEqualTo("atom,node,go,jar,/opt/atom/bin/atom");
        assertThat(CdxgenSbomGenerator.typesFor(Set.of(Language.JAVA, Language.KOTLIN, Language.TYPESCRIPT,
                Language.JAVASCRIPT, Language.GO))).containsOnlyKeys("java", "js", "go");
    }
}
