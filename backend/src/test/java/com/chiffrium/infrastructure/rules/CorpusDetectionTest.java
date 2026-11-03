package com.chiffrium.infrastructure.rules;

import com.chiffrium.TestSupport;
import com.chiffrium.application.port.CryptoDetector.DetectionContext;
import com.chiffrium.application.port.SbomGenerator.SbomResult;
import com.chiffrium.domain.model.CryptoAsset;
import com.chiffrium.infrastructure.scan.FileSystemProjectScanner;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/** Inventaire : cas relevés sur le corpus (OWASP Benchmark, OpenSSL, phpseclib, forge, pycryptodome). */
class CorpusDetectionTest {

    private static List<CryptoAsset> detect(Path project) {
        var scan = new FileSystemProjectScanner(1_000_000).scan(project);
        return new RuleBasedCryptoDetector(new RulePackLoader(TestSupport.MAPPER).loadBuiltIn(), TestSupport.ASSETS)
                .detect(new DetectionContext(project, scan, SbomResult.empty())).assets();
    }

    private static List<String> names(List<CryptoAsset> assets, String file) {
        return assets.stream().filter(a -> a.occurrences().stream().anyMatch(o -> o.file().equals(file)))
                .map(CryptoAsset::name).toList();
    }

    /** Un appel cité dans un message n'est pas un appel ; du XML de signature écrit dans une chaîne reste lu. */
    @Test
    void callsQuotedInMessagesAreIgnored(@TempDir Path project) {
        TestSupport.write(project, "java/BenchmarkTest00003.java", """
                class BenchmarkTest00003 {
                    void run(java.io.PrintWriter out) throws Exception {
                        java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA-256");
                        out.println("Hash Test java.security.MessageDigest.getInstance(java.lang.String) executed");
                        String xml = "<ds:SignatureMethod Algorithm=\\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\\"/>";
                    }
                }
                """);
        TestSupport.write(project, "demos/kdf.c", """
                int main(void) {
                    fprintf(stderr, "EVP_KDF_fetch() returned NULL\\n");
                    return 0;
                }
                """);

        List<CryptoAsset> assets = detect(project);

        assertThat(names(assets, "java/BenchmarkTest00003.java")).contains("SHA-256").noneMatch(n -> n.contains("non résolu"))
                .anyMatch(n -> n.contains("SHA-1withRSA"));
        assertThat(names(assets, "demos/kdf.c")).isEmpty();
    }

    @Test
    void methodsNamedLikeFunctionsAndLibraryCallsAreReadForWhatTheyAre(@TempDir Path project) {
        // $hash->hash($donnees) (phpseclib) : l'argument est la donnée ; hash('sha256', ...) : l'algorithme.
        TestSupport.write(project, "php/PrivateKey.php", """
                <?php
                $m2 = "\\0\\0\\0\\0\\0\\0\\0\\0";
                $h = $this->hash->hash($m2);
                $digest = hash('sha256', $data);
                """);
        TestSupport.write(project, "js/create-cert.js", "var keys = forge.pki.rsa.generateKeyPair(2048);\n");
        TestSupport.write(project, "py/oneshot.py", "import hashlib\n\ndef digest(name, msg):\n    return hashlib.new(name, msg)\n");

        List<CryptoAsset> assets = detect(project);

        assertThat(names(assets, "php/PrivateKey.php")).containsExactly("SHA-256");
        assertThat(names(assets, "js/create-cert.js")).anyMatch(n -> n.startsWith("RSA-2048"));
        assertThat(names(assets, "py/oneshot.py")).containsExactly("hashlib.new (algorithme non résolu)");
    }

    /** L'algorithme lu dans la configuration du projet l'emporte sur la valeur de repli du code (Benchmark). */
    @Test
    void settingsOfTheProjectGiveTheAlgorithmActuallyUsed(@TempDir Path project) {
        TestSupport.write(project, "src/main/resources/benchmark.properties", "# réglages\nhashAlg1=MD5\nhashAlg2 = SHA-256\n");
        TestSupport.write(project, "src/main/resources/application.yml", """
                app:
                  crypto:
                    algorithm: DES/ECB/PKCS5Padding
                """);
        TestSupport.write(project, "src/main/java/Hash.java", """
                class Hash {
                    void run(java.util.Properties benchmarkprops, org.springframework.core.env.Environment env) throws Exception {
                        String algorithm = benchmarkprops.getProperty("hashAlg1", "SHA512");
                        java.security.MessageDigest.getInstance(algorithm);
                        String transformation = env.getProperty("app.crypto.algorithm");
                        javax.crypto.Cipher.getInstance(transformation);
                    }
                }
                """);

        assertThat(names(detect(project), "src/main/java/Hash.java")).contains("MD5")
                .anyMatch(n -> n.startsWith("DES-ECB")).doesNotContain("SHA-512");
    }
}
