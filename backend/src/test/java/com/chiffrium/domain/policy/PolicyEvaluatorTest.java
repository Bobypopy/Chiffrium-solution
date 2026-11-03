package com.chiffrium.domain.policy;

import com.chiffrium.TestSupport;
import com.chiffrium.domain.model.AlgorithmSpec;
import com.chiffrium.domain.model.CryptoAsset;
import com.chiffrium.domain.model.DetectionSource;
import com.chiffrium.domain.model.MaterialInfo;
import com.chiffrium.domain.model.Occurrence;
import com.chiffrium.domain.model.PolicyStatus;
import com.chiffrium.domain.model.PolicyVerdict;
import com.chiffrium.domain.model.Primitive;
import com.chiffrium.domain.model.SecurityStrength;
import com.chiffrium.domain.model.Severity;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

class PolicyEvaluatorTest {

    private static final int THIS_YEAR = 2026;
    private final PolicyEvaluator evaluator = new PolicyEvaluator(TestSupport.CATALOG, TestSupport.clockAt(THIS_YEAR));

    private PolicyVerdict verdict(String raw) {
        return evaluator.evaluateAlgorithm(TestSupport.NORMALIZER.normalize(raw));
    }

    @ParameterizedTest(name = "{0} -> {1}")
    @CsvSource({
            "MD5, disallowed",
            "DES, disallowed",
            "DESede/CBC/PKCS5Padding, disallowed",
            "RC4, disallowed",
            "AES/ECB/PKCS5Padding, disallowed",
            "AES/GCM/NoPadding, recommended",
            "aes-256-gcm, recommended",
            "AES/CBC/PKCS5Padding, acceptable",
            "SHA-256, recommended",
            "SHA-1, deprecated",
            "SHA1withRSA, deprecated",
            "HmacSHA256, recommended",
            "PBEWithMD5AndDES, disallowed",
            "TLSv1, disallowed",
            "TLSv1.3, recommended",
            "SSLv3, disallowed",
            "ML-KEM-768, recommended",
            "SHA1PRNG, deprecated",
            "JWT alg=none, disallowed"
    })
    void evaluatesAlgorithms(String raw, String expectedStatus) {
        assertThat(verdict(raw).status()).isEqualTo(PolicyStatus.fromId(expectedStatus));
    }

    @Test
    void rsaDependsOnKeySizeAndYear() {
        AlgorithmSpec rsa = TestSupport.NORMALIZER.normalize("RSA");
        assertThat(evaluator.evaluateAlgorithm(rsa.withKeySize(1024)).status()).isEqualTo(PolicyStatus.DISALLOWED);

        PolicyVerdict rsa2048 = evaluator.evaluateAlgorithm(rsa.withKeySize(2048));
        assertThat(rsa2048.status()).isEqualTo(PolicyStatus.ACCEPTABLE);
        assertThat(rsa2048.quantumVulnerable()).isTrue();
        assertThat(rsa2048.severity()).isEqualTo(Severity.LOW);
        assertThat(rsa2048.validUntil()).isEqualTo(2030);

        PolicyEvaluator in2031 = new PolicyEvaluator(TestSupport.CATALOG, TestSupport.clockAt(2031));
        assertThat(in2031.evaluateAlgorithm(rsa.withKeySize(2048)).status()).isEqualTo(PolicyStatus.DEPRECATED);
        assertThat(in2031.evaluateAlgorithm(rsa.withKeySize(3072)).status()).isEqualTo(PolicyStatus.ACCEPTABLE);

        PolicyEvaluator in2036 = new PolicyEvaluator(TestSupport.CATALOG, TestSupport.clockAt(2036));
        assertThat(in2036.evaluateAlgorithm(rsa.withKeySize(4096)).status()).isEqualTo(PolicyStatus.DISALLOWED);
    }

    @Test
    void unknownKeySizeIsReportedButNotPenalized() {
        PolicyVerdict verdict = verdict("RSA");
        assertThat(verdict.status()).isEqualTo(PolicyStatus.ACCEPTABLE);
        assertThat(verdict.reasons()).anyMatch(r -> r.contains("taille de clé non déterminée"));
    }

    @Test
    void sha1BecomesDisallowedAfter2030() {
        PolicyEvaluator in2031 = new PolicyEvaluator(TestSupport.CATALOG, TestSupport.clockAt(2031));
        assertThat(in2031.evaluateAlgorithm(TestSupport.NORMALIZER.normalize("SHA-1")).status())
                .isEqualTo(PolicyStatus.DISALLOWED);
    }

    @Test
    void unknownAlgorithmsAreFlaggedForReview() {
        PolicyVerdict verdict = verdict("HomeMadeCipher");
        assertThat(verdict.status()).isEqualTo(PolicyStatus.UNKNOWN);
        assertThat(verdict.recommendation()).isNotBlank();
    }

    @Test
    void committedPrivateKeyIsCritical() {
        CryptoAsset key = TestSupport.ASSETS.material("keys/id_rsa", MaterialInfo.of("private-key", "PEM"), null,
                occurrence("keys/id_rsa"));
        PolicyVerdict verdict = evaluator.evaluate(key).verdict();
        assertThat(verdict.status()).isEqualTo(PolicyStatus.DISALLOWED);
        assertThat(verdict.severity()).isEqualTo(Severity.CRITICAL);

        CryptoAsset encrypted = TestSupport.ASSETS.material("keys/enc.pem",
                MaterialInfo.of("private-key", "PEM ENCRYPTED"), null, occurrence("keys/enc.pem"));
        assertThat(evaluator.evaluate(encrypted).verdict().severity()).isEqualTo(Severity.HIGH);
    }

    @Test
    void postQuantumLevelsFollowAnssiBsiAndCnsa() {
        assertThat(verdict("ML-DSA-44").status()).isEqualTo(PolicyStatus.DEPRECATED);
        // Niveau 3 : recommandé par l'ANSSI et le BSI, l'exigence CNSA 2.0 est signalée sans dégrader le statut.
        PolicyVerdict mlDsa65 = verdict("ML-DSA-65");
        assertThat(mlDsa65.status()).isEqualTo(PolicyStatus.RECOMMENDED);
        assertThat(mlDsa65.reasons()).anyMatch(r -> r.startsWith("ML-DSA-65 : CNSA 2.0"));
        assertThat(verdict("ML-DSA-87").reasons()).noneMatch(r -> r.contains("CNSA"));
        assertThat(verdict("ML-KEM-512").status()).isEqualTo(PolicyStatus.DEPRECATED);
        assertThat(verdict("ML-KEM-768").reasons()).anyMatch(r -> r.startsWith("ML-KEM-768 : CNSA 2.0"));
        assertThat(verdict("ML-KEM-1024").status()).isEqualTo(PolicyStatus.RECOMMENDED);
        assertThat(verdict("ML-KEM").reasons()).anyMatch(r -> r.contains("niveau de sécurité non déterminé"));
    }

    /**
     * Ce qui résiste au quantique : catégorie NIST 1 à 5 (AES-128 = 1, ML-KEM-768 = 3, AES-256 = 5), 0 pour ce que
     * Shor casse quelle que soit la taille ; aucun niveau affirmé quand les paramètres manquent.
     */
    @ParameterizedTest(name = "{0} -> {1} bits, catégorie {2}")
    @CsvSource(nullValues = "-", value = {
            "ML-KEM-512, 128, 1",
            "ML-KEM-768, 192, 3",
            "ML-DSA-44, 128, 2",
            "ML-DSA-87, 256, 5",
            "SLH-DSA-SHA2-192s, 192, 3",
            "AES-128/GCM/NoPadding, 128, 1",
            "AES-256-GCM, 256, 5",
            "ChaCha20-Poly1305, 256, 5",
            "DESede/CBC/PKCS5Padding, 112, 0",
            "SHA-256, 128, 2",
            "SHA-384, 192, 4",
            "RSA-2048, 112, 0",
            "RSA-4096, 128, 0",
            "ECDH-P-384, 192, 0",
            "Ed25519, 128, 0",
            "SHA256withRSA, -, 0",
    })
    void securityLevelsSayWhatWithstandsAQuantumComputer(String raw, Integer classicalBits, Integer level) {
        assertThat(verdict(raw).strength()).isEqualTo(new SecurityStrength(classicalBits, level));
    }

    @ParameterizedTest
    @CsvSource({"AES/GCM/NoPadding", "ML-KEM", "HmacSHA256", "PBKDF2WithHmacSHA256"})
    void noLevelIsClaimedWithoutTheParameters(String raw) {
        assertThat(verdict(raw).strength()).isNull();
    }

    /** Un algorithme cassé par Shor reçoit toujours une cible de migration, même absente du catalogue. */
    @Test
    void everyQuantumVulnerableAlgorithmGetsAMigrationTarget() {
        for (AlgorithmDefinition definition : TestSupport.CATALOG.algorithms()) {
            if (definition.quantumVulnerable()) {
                assertThat(verdict(definition.name()).recommendation()).as(definition.id()).isNotBlank();
            }
        }
        assertThat(PolicyEvaluator.migrationTarget(Primitive.SIGNATURE)).contains("ML-DSA");
        assertThat(PolicyEvaluator.migrationTarget(Primitive.KEY_AGREEMENT)).contains("ML-KEM");
    }

    @Test
    void generatedKeyIsJudgedByItsAlgorithmNotAsACommittedKey() {
        AlgorithmSpec rsa1024 = TestSupport.NORMALIZER.normalize("RSA").withKeySize(1024);
        CryptoAsset key = TestSupport.ASSETS.generatedKey("private-key", rsa1024, occurrence("src/Keys.java"));
        PolicyVerdict verdict = evaluator.evaluate(key).verdict();
        assertThat(verdict).isEqualTo(evaluator.evaluateAlgorithm(rsa1024));
        assertThat(verdict.status()).isEqualTo(PolicyStatus.DISALLOWED);
        assertThat(verdict.severity()).isNotEqualTo(Severity.CRITICAL);
    }

    @Test
    void expiredCertificateIsDisallowed() {
        MaterialInfo material = new MaterialInfo("certificate", "PEM", "CN=test", "CN=test",
                "2020-01-01T00:00:00Z", "2021-01-01T00:00:00Z", false);
        CryptoAsset cert = TestSupport.ASSETS.certificate("cert.pem", 0,
                TestSupport.NORMALIZER.normalize("SHA256withRSA").withKeySize(2048), material, occurrence("cert.pem"));
        PolicyVerdict verdict = evaluator.evaluate(cert).verdict();
        assertThat(verdict.status()).isEqualTo(PolicyStatus.DISALLOWED);
        assertThat(verdict.reasons()).anyMatch(r -> r.contains("expiré"));
    }

    private static Occurrence occurrence(String file) {
        return new Occurrence(file, 1, null, null, null, null, DetectionSource.MATERIAL, "test", Set.of());
    }
}
