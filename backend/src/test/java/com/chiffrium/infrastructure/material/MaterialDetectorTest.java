package com.chiffrium.infrastructure.material;

import com.chiffrium.TestSupport;
import com.chiffrium.application.port.CryptoDetector.DetectionContext;
import com.chiffrium.application.port.SbomGenerator.SbomResult;
import com.chiffrium.domain.model.AssetType;
import com.chiffrium.domain.model.CryptoAsset;
import com.chiffrium.domain.model.PolicyStatus;
import com.chiffrium.domain.model.Severity;
import com.chiffrium.domain.policy.PolicyEvaluator;
import com.chiffrium.infrastructure.scan.FileSystemProjectScanner;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class MaterialDetectorTest {

    @TempDir
    static Path project;
    private static List<CryptoAsset> assets;

    @BeforeAll
    static void detect() throws Exception {
        Files.createDirectories(project.resolve("certs"));
        for (String name : List.of("valid-sha256.crt", "expired.pem", "weak-rsa1024.crt", "test-private.key",
                "test-public.pem")) {
            Files.copy(TestSupport.fixture("material/" + name), project.resolve("certs").resolve(name));
        }
        Files.write(project.resolve("certs/store.p12"), new byte[]{1, 2, 3});
        String key = Files.readString(TestSupport.fixture("material/test-private.key"));
        TestSupport.write(project, "src/Keys.java", "class Keys { String k = \"" + key.lines().findFirst().orElseThrow()
                + "\\nMIIB...\"; }");

        var scan = new FileSystemProjectScanner(1_000_000).scan(project);
        PolicyEvaluator evaluator = new PolicyEvaluator(TestSupport.CATALOG, TestSupport.clockAt(2026));
        assets = new MaterialDetector(TestSupport.ASSETS)
                .detect(new DetectionContext(project, scan, SbomResult.empty()))
                .assets().stream().map(evaluator::evaluate).toList();
    }

    private static CryptoAsset inFile(String file) {
        return assets.stream().filter(a -> a.occurrences().get(0).file().equals(file)).findFirst()
                .orElseThrow(() -> new AssertionError("Rien dans " + file));
    }

    @Test
    void parsesValidCertificate() {
        CryptoAsset cert = inFile("certs/valid-sha256.crt");
        assertThat(cert.assetType()).isEqualTo(AssetType.CERTIFICATE);
        assertThat(cert.material().subject()).contains("valid.chiffrium.test");
        assertThat(cert.algorithm().displayName()).isEqualTo("SHA-256withRSA-2048");
        assertThat(cert.verdict().status()).isEqualTo(PolicyStatus.ACCEPTABLE);
    }

    @Test
    void flagsExpiredAndWeakCertificates() {
        assertThat(inFile("certs/expired.pem").verdict().status()).isEqualTo(PolicyStatus.DISALLOWED);
        CryptoAsset weak = inFile("certs/weak-rsa1024.crt");
        assertThat(weak.algorithm().keySize()).isEqualTo(1024);
        assertThat(weak.verdict().status()).isEqualTo(PolicyStatus.DISALLOWED);
    }

    @Test
    void flagsCommittedPrivateKeysIncludingEmbeddedOnes() {
        CryptoAsset key = inFile("certs/test-private.key");
        assertThat(key.material().materialType()).isEqualTo("private-key");
        assertThat(key.verdict().severity()).isEqualTo(Severity.CRITICAL);
        assertThat(inFile("src/Keys.java").material().format()).contains("embarqué");
    }

    @Test
    void inspectsPublicKeysAndKeystores() {
        CryptoAsset publicKey = inFile("certs/test-public.pem");
        assertThat(publicKey.algorithm().displayName()).isEqualTo("RSA-2048");
        assertThat(inFile("certs/store.p12").material().materialType()).isEqualTo("keystore");
        assertThat(inFile("certs/store.p12").verdict().status()).isEqualTo(PolicyStatus.DEPRECATED);
    }

    /** Régression (bc-java) : une clé DSA sans paramètres faisait échouer toute la détection du matériel. */
    @Test
    void toleratesKeysWithoutDomainParameters() {
        java.security.interfaces.DSAPublicKey dsa = new java.security.interfaces.DSAPublicKey() {
            @Override
            public java.math.BigInteger getY() {
                return java.math.BigInteger.ONE;
            }

            @Override
            public java.security.interfaces.DSAParams getParams() {
                return null;
            }

            @Override
            public String getAlgorithm() {
                return "DSA";
            }

            @Override
            public String getFormat() {
                return "X.509";
            }

            @Override
            public byte[] getEncoded() {
                return new byte[0];
            }
        };
        assertThat(KeyInspector.describe(dsa)).contains(new KeyInspector.KeyInfo("DSA", null));
    }
}
