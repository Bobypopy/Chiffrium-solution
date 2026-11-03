package com.chiffrium.infrastructure.persistence;

import com.chiffrium.SecurityFixture;
import com.chiffrium.TestSupport;
import com.chiffrium.application.CatalogService;
import com.chiffrium.application.port.AnalysisRepository.Artifact;
import com.chiffrium.application.security.AccessDeniedException;
import com.chiffrium.application.security.Actor;
import com.chiffrium.domain.model.AnalysisIds;
import com.chiffrium.domain.model.AnalysisJob;
import com.chiffrium.domain.model.AnalysisRequest;
import com.chiffrium.domain.model.AnalysisStatus;
import com.chiffrium.domain.model.PolicyStatus;
import com.chiffrium.domain.policy.AlgorithmCatalog;
import com.chiffrium.domain.policy.AlgorithmDefinition;
import com.chiffrium.domain.policy.ParameterDefinition;
import com.chiffrium.domain.security.Role;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class PersistenceTest {

    private static final AnalysisRequest REQUEST =
            new AnalysisRequest("https://example.org/a.git", null, true, true, true, null);
    private static final String REQUESTER = "alice";

    private static FileSystemAnalysisRepository repository(Path dir) {
        return new FileSystemAnalysisRepository(dir, TestSupport.MAPPER, TestSupport.cipher());
    }

    @Test
    void savesListsAndDeletesAnalyses(@TempDir Path dir) {
        FileSystemAnalysisRepository repository = repository(dir);
        AnalysisJob older = AnalysisJob.queued(UUID.randomUUID().toString(), REQUEST, REQUESTER,
                Instant.parse("2026-01-01T00:00:00Z"));
        AnalysisJob newer = AnalysisJob.queued(UUID.randomUUID().toString(), REQUEST, REQUESTER,
                Instant.parse("2026-02-01T00:00:00Z"));
        repository.save(older);
        repository.save(newer.started(Instant.now()));

        assertThat(repository.findAll()).extracting(AnalysisJob::id).containsExactly(newer.id(), older.id());
        assertThat(repository.find(newer.id())).get().extracting(AnalysisJob::status).isEqualTo(AnalysisStatus.RUNNING);
        assertThat(repository.find(newer.id())).get().extracting(AnalysisJob::requestedBy).isEqualTo(REQUESTER);
        assertThat(repository.readArtifact(older.id(), Artifact.REPORT)).isEmpty();

        repository.delete(older.id());
        assertThat(repository.find(older.id())).isEmpty();
    }

    @Test
    void artifactsAreEncryptedAtRestAndRawOutputsDropped(@TempDir Path dir) throws Exception {
        FileSystemAnalysisRepository repository = repository(dir);
        AnalysisJob job = AnalysisJob.queued(UUID.randomUUID().toString(), REQUEST, REQUESTER, Instant.now());
        repository.save(job);
        Path work = repository.artifactsDir(job.id());
        Files.writeString(work.resolve(Artifact.CBOM.fileName()), "{\"bomFormat\":\"CycloneDX\"}");
        Files.writeString(work.resolve(Artifact.LOG.fileName()), "Étape 1");
        Files.createDirectories(work.resolve("raw"));
        Files.writeString(work.resolve("raw/bom.json"), "{}");

        repository.seal(job.id(), false);

        assertThat(Files.readString(work.resolve(Artifact.CBOM.fileName()), StandardCharsets.ISO_8859_1))
                .doesNotContain("CycloneDX");
        assertThat(Files.readString(work.resolve("analysis.json"), StandardCharsets.ISO_8859_1))
                .doesNotContain("example.org");
        assertThat(work.resolve("raw")).doesNotExist();
        assertThat(new String(repository.readArtifact(job.id(), Artifact.CBOM).orElseThrow(), StandardCharsets.UTF_8))
                .contains("CycloneDX");
        assertThat(repository.sizeOf(job.id())).isPositive();

        // Un fichier en clair d'une version précédente reste lisible.
        Files.writeString(work.resolve(Artifact.SARIF.fileName()), "{\"version\":\"2.1.0\"}");
        assertThat(repository.readArtifact(job.id(), Artifact.SARIF)).isPresent();
    }

    @Test
    void refusesPathTraversalIdentifiers(@TempDir Path dir) {
        FileSystemAnalysisRepository repository = repository(dir);
        assertThat(repository.find("../../etc")).isEmpty();
        assertThat(AnalysisIds.isValid("../x")).isFalse();
        assertThatThrownBy(() -> repository.artifactsDir("..")).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void catalogIsInitializedValidatedBackedUpAndAudited(@TempDir Path dir) {
        Path file = dir.resolve("catalog/algorithms.json");
        FileCatalogRepository repository = new FileCatalogRepository(file, TestSupport.MAPPER);
        assertThat(file).exists();
        try (SecurityFixture fx = new SecurityFixture(dir)) {
            CatalogService service = new CatalogService(repository, fx.audit);
            Actor admin = new Actor("1", "admin", Role.ADMIN, null);
            Actor analyst = new Actor("2", "alice", Role.ANALYST, null);

            AlgorithmDefinition custom = new AlgorithmDefinition("custom-cipher", "CustomCipher", null, null,
                    List.of("customcipher"), List.of(), List.of(), null, false, null, null, null, "test", null, List.of());
            assertThatThrownBy(() -> service.upsert(analyst, custom)).isInstanceOf(AccessDeniedException.class);
            service.upsert(admin, custom);
            assertThat(file.resolveSibling("algorithms.json.bak")).exists();
            assertThat(new FileCatalogRepository(file, TestSupport.MAPPER).load().findAlgorithm("custom-cipher")).isPresent();

            AlgorithmDefinition invalid = new AlgorithmDefinition("custom-cipher", "CustomCipher", null, null,
                    List.of("Not Valid"), List.of(), List.of(), null, false, null, null, null, null, null, List.of());
            assertThatThrownBy(() -> service.upsert(admin, invalid)).isInstanceOf(CatalogService.InvalidCatalogException.class);

            service.remove(admin, "custom-cipher");
            assertThat(service.catalog().findAlgorithm("custom-cipher")).isEmpty();
            assertThat(fx.audit.search("admin", null, 10, 0)).extracting(e -> e.action())
                    .contains("CATALOG_ENTRY_CREATED", "CATALOG_ENTRY_DELETED");
        }
    }

    @Test
    void newDefaultEntriesAreMergedWithoutRestoringDeletedOnes(@TempDir Path dir) {
        Path file = dir.resolve("catalog/algorithms.json");
        AlgorithmCatalog defaults = FileCatalogRepository.loadDefault(TestSupport.MAPPER);
        // Catalogue d'une version antérieure : sans Ascon ni SIKE, MD5 reclassé par l'organisation.
        AlgorithmDefinition md5 = defaults.findAlgorithm("md5").orElseThrow();
        AlgorithmDefinition md5Custom = new AlgorithmDefinition(md5.id(), md5.name(), md5.primitive(), md5.assetType(),
                md5.aliases(), md5.tokens(), md5.oids(), PolicyStatus.DEPRECATED, md5.quantumVulnerable(),
                md5.keySizeRules(), null, null, "Toléré pour les empreintes non sensibles", null, md5.references());
        List<AlgorithmDefinition> old = new ArrayList<>(defaults.algorithms().stream()
                .filter(a -> !a.id().equals("ascon") && !a.id().equals("sike") && !a.id().equals("md5")).toList());
        old.add(md5Custom);
        AtomicFiles.writeJson(TestSupport.MAPPER, file,
                new AlgorithmCatalog(defaults.schemaVersion(), old, defaults.modes(), defaults.paddings(),
                        defaults.curves()));

        AlgorithmCatalog upgraded = new FileCatalogRepository(file, TestSupport.MAPPER).load();
        assertThat(upgraded.findAlgorithm("ascon")).isPresent();
        assertThat(upgraded.findAlgorithm("sike")).isPresent();
        assertThat(upgraded.findAlgorithm("md5").orElseThrow().status()).as("choix local conservé")
                .isEqualTo(PolicyStatus.DEPRECATED);

        // Une entrée supprimée ensuite par l'organisation ne revient pas au démarrage suivant.
        FileCatalogRepository repository = new FileCatalogRepository(file, TestSupport.MAPPER);
        repository.save(new AlgorithmCatalog(upgraded.schemaVersion(), upgraded.algorithms().stream()
                .filter(a -> !a.id().equals("sike")).toList(), upgraded.modes(), upgraded.paddings(), upgraded.curves()));
        assertThat(new FileCatalogRepository(file, TestSupport.MAPPER).load().findAlgorithm("sike")).isEmpty();
    }

    @Test
    void existingPostQuantumEntriesReceiveTheirLevelRulesOnce(@TempDir Path dir) {
        Path file = dir.resolve("catalog/algorithms.json");
        AlgorithmCatalog defaults = FileCatalogRepository.loadDefault(TestSupport.MAPPER);
        // Catalogue d'une version antérieure : ML-DSA présent, mais sans règles de niveau.
        List<AlgorithmDefinition> old = defaults.algorithms().stream()
                .map(a -> !a.id().equals("ml-dsa") ? a : new AlgorithmDefinition(a.id(), a.name(), a.primitive(),
                        a.assetType(), a.aliases(), a.tokens(), a.oids(), a.status(), a.quantumVulnerable(), List.of(),
                        null, null, a.note(), a.recommendation(), a.references()))
                .toList();
        AtomicFiles.writeJson(TestSupport.MAPPER, file,
                new AlgorithmCatalog(defaults.schemaVersion(), old, defaults.modes(), defaults.paddings(),
                        defaults.curves()));

        FileCatalogRepository repository = new FileCatalogRepository(file, TestSupport.MAPPER);
        AlgorithmCatalog upgraded = repository.load();
        assertThat(upgraded.findAlgorithm("ml-dsa").orElseThrow().keySizeRules())
                .isEqualTo(defaults.findAlgorithm("ml-dsa").orElseThrow().keySizeRules());

        // Retirées ensuite par l'organisation, elles ne reviennent pas.
        repository.save(new AlgorithmCatalog(upgraded.schemaVersion(), old, upgraded.modes(), upgraded.paddings(),
                upgraded.curves()));
        assertThat(new FileCatalogRepository(file, TestSupport.MAPPER).load().findAlgorithm("ml-dsa").orElseThrow()
                .keySizeRules()).isEmpty();
    }

    @Test
    void outdatedOidsAreReplacedOnceUnlessTheOrganisationAddedItsOwn(@TempDir Path dir) {
        Path file = dir.resolve("catalog/algorithms.json");
        AlgorithmCatalog defaults = FileCatalogRepository.loadDefault(TestSupport.MAPPER);
        // Catalogue de la 1.2.0 : racine de famille pour AES, un seul OID pour ML-KEM, courbes sans OID, et un OID
        // ajouté par l'organisation à RC4.
        Map<String, List<AlgorithmDefinition.OidRef>> before = Map.of(
                "aes", List.of(new AlgorithmDefinition.OidRef("2.16.840.1.101.3.4.1", "NIST AES")),
                "ml-kem", List.of(new AlgorithmDefinition.OidRef("2.16.840.1.101.3.4.4.2", "id-alg-ml-kem-768")),
                "rc4", List.of(new AlgorithmDefinition.OidRef("1.2.840.113549.3.4", "rc4"),
                        new AlgorithmDefinition.OidRef("1.3.6.1.4.1.99999.1", "OID interne")));
        List<AlgorithmDefinition> old = defaults.algorithms().stream()
                .map(a -> !before.containsKey(a.id()) ? a : new AlgorithmDefinition(a.id(), a.name(), a.primitive(),
                        a.assetType(), a.aliases(), a.tokens(), before.get(a.id()), a.status(), a.quantumVulnerable(),
                        a.keySizeRules(), a.deprecatedAfter(), a.disallowedAfter(), "Note de l'organisation",
                        a.recommendation(), a.references()))
                .toList();
        List<ParameterDefinition> curves = defaults.curves().stream()
                .map(c -> new ParameterDefinition(c.id(), c.name(), c.aliases(), c.tokens(), c.status(), c.note(), null))
                .toList();
        AtomicFiles.writeJson(TestSupport.MAPPER, file,
                new AlgorithmCatalog(defaults.schemaVersion(), old, defaults.modes(), defaults.paddings(), curves));

        FileCatalogRepository repository = new FileCatalogRepository(file, TestSupport.MAPPER);
        AlgorithmCatalog upgraded = repository.load();
        AlgorithmDefinition aes = upgraded.findAlgorithm("aes").orElseThrow();
        assertThat(aes.oids()).isEqualTo(defaults.findAlgorithm("aes").orElseThrow().oids());
        assertThat(aes.note()).as("le reste de l'entrée ne change pas").isEqualTo("Note de l'organisation");
        assertThat(upgraded.findAlgorithm("ml-kem").orElseThrow().oids()).hasSize(3);
        assertThat(upgraded.findAlgorithm("rc4").orElseThrow().oids()).as("OID de l'organisation conservé")
                .isEqualTo(before.get("rc4"));
        assertThat(upgraded.findCurve("P-256").orElseThrow().oids()).extracting(AlgorithmDefinition.OidRef::oid)
                .containsExactly("1.2.840.10045.3.1.7");

        // Retirés ensuite par l'organisation, ils ne reviennent pas.
        repository.save(new AlgorithmCatalog(upgraded.schemaVersion(), old, upgraded.modes(), upgraded.paddings(),
                upgraded.curves()));
        assertThat(new FileCatalogRepository(file, TestSupport.MAPPER).load().findAlgorithm("aes").orElseThrow()
                .oids()).isEqualTo(before.get("aes"));
    }

    @Test
    void corruptedJobFilesAreIgnored(@TempDir Path dir) throws Exception {
        FileSystemAnalysisRepository repository = repository(dir);
        String id = UUID.randomUUID().toString();
        Files.createDirectories(dir.resolve(id));
        Files.writeString(dir.resolve(id).resolve("analysis.json"), "{ not json");
        assertThat(repository.findAll()).isEmpty();
    }
}
