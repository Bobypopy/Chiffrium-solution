package com.chiffrium.domain.policy;

import com.chiffrium.TestSupport;
import com.chiffrium.domain.model.AlgorithmSpec;
import com.chiffrium.domain.model.CryptoAsset;
import com.chiffrium.domain.model.DetectionSource;
import com.chiffrium.domain.model.MaterialInfo;
import com.chiffrium.domain.model.Occurrence;
import com.chiffrium.domain.model.PolicyStatus;
import com.chiffrium.domain.model.PolicyVerdict;
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
