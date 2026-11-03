package com.chiffrium.infrastructure.findings;

import com.chiffrium.TestSupport;
import com.chiffrium.application.port.CryptoDetector.DetectionContext;
import com.chiffrium.application.port.SbomGenerator.SbomResult;
import com.chiffrium.domain.model.SecurityFinding;
import com.chiffrium.infrastructure.rules.RulePackLoader;
import com.chiffrium.infrastructure.scan.FileSystemProjectScanner;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/** Constats dont la valeur arrive par un paramètre, un champ ou une autre classe. */
class TracedFindingsTest {

    @TempDir
    static Path project;
    private static List<SecurityFinding> findings;

    @BeforeAll
    static void analyze() {
        TestSupport.write(project, "java/Crypto.java", """
                public class Crypto {
                    public void encrypt(byte[] iv, byte[] seed, int rounds, String password) throws Exception {
                        javax.crypto.spec.IvParameterSpec spec = new javax.crypto.spec.IvParameterSpec(iv);
                        java.security.SecureRandom random = new java.security.SecureRandom();
                        random.setSeed(seed);
                        javax.crypto.spec.PBEKeySpec pbe = new javax.crypto.spec.PBEKeySpec(password.toCharArray(),
                                iv, rounds, 256);
                    }
                    public void key(String text) {
                        byte[] bytes = text.getBytes();
                        bytes = java.util.Arrays.copyOf(bytes, 16);
                        new javax.crypto.spec.SecretKeySpec(bytes, "AES");
                    }
                }
                """);
        TestSupport.write(project, "java/Main.java", """
                public class Main {
                    public static void main(String[] args) throws Exception {
                        Crypto crypto = new Crypto();
                        byte[] iv = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
                        crypto.encrypt(iv, new byte[]{(byte) 100}, 1000, "Sup3rS3cret!");
                        crypto.key("my-hardcoded-aes-key");
                    }
                }
                """);
        // Tampon rempli par l'aléa avant usage : rien à signaler.
        TestSupport.write(project, "java/Safe.java", """
                public class Safe {
                    public static void main(String[] args) throws Exception {
                        byte[] iv = new byte[16];
                        new java.security.SecureRandom().nextBytes(iv);
                        new Crypto().encrypt(iv, iv, 600000, System.getenv("PASSWORD"));
                    }
                }
                """);
        TestSupport.write(project, "py/vault.py", """
                from Crypto.Cipher import AES

                def seal(key, data):
                    return AES.new(key, AES.MODE_GCM).encrypt(data)

                def run():
                    return seal(b"0123456789abcdef", b"x")
                """);
        TestSupport.write(project, "js/vault.js", """
                const crypto = require('crypto');
                function derive(password, salt, rounds) { return crypto.pbkdf2Sync(password, salt, rounds, 32, 'sha256'); }
                function run(p, s) { return derive(p, s, 5000); }
                """);

        var scan = new FileSystemProjectScanner(1_000_000).scan(project);
        findings = new SecurityFindingDetector(new FindingRuleLoader(TestSupport.MAPPER).loadBuiltIn(),
                new RulePackLoader(TestSupport.MAPPER).loadBuiltIn())
                .detect(new DetectionContext(project, scan, SbomResult.empty())).findings();
    }

    private static List<SecurityFinding> of(String ruleId) {
        return findings.stream().filter(f -> f.ruleId().equals(ruleId)).toList();
    }

    @Test
    void staticIvPassedAsParameterIsReportedAtTheCallAndWhereItIsWritten() {
        assertThat(of("iv-java-traced")).extracting(SecurityFinding::file, SecurityFinding::line)
                .contains(org.assertj.core.groups.Tuple.tuple("java/Crypto.java", 3),
                        org.assertj.core.groups.Tuple.tuple("java/Main.java", 4));
        assertThat(of("iv-java-traced")).anySatisfy(f -> assertThat(f.description()).contains("Main.main"));
    }

    @Test
    void seedIterationsAndPasswordAreTraced() {
        assertThat(of("random-seed-traced")).extracting(SecurityFinding::file).contains("java/Crypto.java");
        assertThat(of("kdf-java-iterations-traced")).anySatisfy(f -> {
            assertThat(f.file()).isEqualTo("java/Crypto.java");
            assertThat(f.evidence()).startsWith("1000 (<");
        });
        assertThat(of("secret-java-pbe-password-traced")).anySatisfy(f ->
                assertThat(f.evidence()).doesNotContain("Sup3rS3cret!"));
    }

    @Test
    void keyBuiltFromAStringIsASecret() {
        assertThat(of("secret-java-key-from-string-traced")).extracting(SecurityFinding::file)
                .contains("java/Crypto.java", "java/Main.java");
    }

    @Test
    void bufferFilledWithRandomnessOrComputedValuesAreNotReported() {
        assertThat(findings).noneMatch(f -> f.file().equals("java/Safe.java"));
        // Safe passe 600000 itérations et un mot de passe lu dans l'environnement : rien de plus qu'avec Main.
        assertThat(of("kdf-java-iterations-traced")).noneMatch(f -> f.evidence().startsWith("600000"));
    }

    @Test
    void otherLanguagesAreTraced() {
        assertThat(of("key-python-traced")).extracting(SecurityFinding::file).contains("py/vault.py");
        assertThat(of("kdf-js-iterations-traced")).extracting(SecurityFinding::file).contains("js/vault.js");
    }
}
