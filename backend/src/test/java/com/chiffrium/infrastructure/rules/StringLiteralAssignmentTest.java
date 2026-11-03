package com.chiffrium.infrastructure.rules;

import com.chiffrium.TestSupport;
import com.chiffrium.application.port.CryptoDetector.DetectionContext;
import com.chiffrium.application.port.SbomGenerator.SbomResult;
import com.chiffrium.domain.model.CryptoAsset;
import com.chiffrium.infrastructure.scan.FileSystemProjectScanner;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;

import static org.assertj.core.api.Assertions.assertThat;

/** Un texte affiché ("Rsa{algorithmId=" + algorithmId) n'est pas une affectation : bc-java, pgsc et prov. */
class StringLiteralAssignmentTest {

    @Test
    void textInsideAStringIsNotAnAssignment(@TempDir Path project) {
        TestSupport.write(project, "prov/BcFKSKeyStoreSpi.java", """
                class BcFKSKeyStoreSpi {
                    private byte[] calculateMac(byte[] content, AlgorithmIdentifier algorithm) throws Exception {
                        String algorithmId = algorithm.getAlgorithm().getId();
                        javax.crypto.Mac mac = javax.crypto.Mac.getInstance(algorithmId);
                        return mac.doFinal(content);
                    }
                }
                """);
        TestSupport.write(project, "pgsc/SupportedAlgorithms.java", """
                class SupportedAlgorithms {
                    static class Rsa {
                        private final int algorithmId;
                        private final int keySize;
                        Rsa(int algorithmId, int keySize) {
                            this.algorithmId = algorithmId;
                            this.keySize = keySize;
                        }
                        @Override
                        public String toString() {
                            return "Rsa{algorithmId=" + algorithmId + ", keySize=" + keySize + '}';
                        }
                    }
                }
                """);

        var scan = new FileSystemProjectScanner(1_000_000).scan(project);
        var result = new RuleBasedCryptoDetector(new RulePackLoader(TestSupport.MAPPER).loadBuiltIn(), TestSupport.ASSETS)
                .detect(new DetectionContext(project, scan, SbomResult.empty()));

        assertThat(result.assets()).extracting(CryptoAsset::name).noneMatch(name -> name.contains("algorithmId"))
                .anyMatch(name -> name.startsWith("Mac"));
    }

    @Test
    void positionsInsideAStringAreRecognised() {
        String line = "return \"Rsa{algorithmId=\" + algorithmId + ', ' + \"a\\\"b=\" + x;";
        assertThat(StringLiterals.inside(line, line.indexOf("algorithmId="), true)).isTrue();
        assertThat(StringLiterals.inside(line, line.indexOf("+ algorithmId") + 2, true)).isFalse();
        assertThat(StringLiterals.inside(line, line.indexOf("b="), true)).isTrue();
        // Durée de vie Rust : l'apostrophe n'ouvre pas de chaîne.
        String rust = "fn f<'a>(x: &'a str) { let algo = x; }";
        assertThat(StringLiterals.inside(rust, rust.indexOf("algo ="), false)).isFalse();
    }
}
