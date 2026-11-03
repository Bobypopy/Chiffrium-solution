package com.chiffrium.infrastructure.findings;

import com.chiffrium.TestSupport;
import com.chiffrium.application.port.CryptoDetector.DetectionContext;
import com.chiffrium.application.port.SbomGenerator.SbomResult;
import com.chiffrium.domain.model.SecurityFinding;
import com.chiffrium.domain.model.Severity;
import com.chiffrium.infrastructure.rules.RulePackLoader;
import com.chiffrium.infrastructure.scan.FileSystemProjectScanner;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Cas relevés sur un corpus de 28 projets (OpenSSL, bc-csharp, forge, Vault, Bitwarden, WebGoat, phpseclib, pyca,
 * ruby/openssl, spring-security, OWASP Benchmark...) : ce qui n'est pas un constat, et ce qui en reste un.
 */
class CorpusFindingsTest {

    private static final FindingRuleLoader.FindingRuleSet RULES = new FindingRuleLoader(TestSupport.MAPPER).loadBuiltIn();

    private static List<SecurityFinding> detect(Path root) {
        DetectionContext context = new DetectionContext(root, new FileSystemProjectScanner(1_000_000).scan(root),
                SbomResult.empty());
        return new SecurityFindingDetector(RULES, new RulePackLoader(TestSupport.MAPPER).loadBuiltIn())
                .detect(context).findings();
    }

    @Test
    void valuesCommentsRegistriesBuildersReferencesAndImportsAreNotFindings(@TempDir Path root) {
        // Valeur nulle et commentaire lus comme des listes de suites (OpenSSL, Mbed TLS, bc-csharp, Bitwarden, forge).
        TestSupport.write(root, "apps/ciphers.c", """
                char *ciphers = NULL, *prog, *convert = NULL, *ciphersuites = NULL;
                int force_ciphersuite[2];   /* protocol/ciphersuite to use, or all      */
                #define SSL3_RFC_RSA_NULL_MD5 "TLS_RSA_WITH_NULL_MD5"
                static const ssl_trace_tbl ssl_ciphers_tbl[] = {
                    { 0x0003, "TLS_RSA_EXPORT_WITH_RC4_40_MD5" },
                };
                """);
        TestSupport.write(root, "crypto/objects/objects.txt", "# Synthetic composite ciphersuites\n"
                + "ISO-US 1 : RC4-HMAC-MD5 : rc4-hmac-md5\n");
        TestSupport.write(root, "tls/AbstractTlsServer.cs", """
                class AbstractTlsServer {
                    void Reset() {
                        m_offeredCipherSuites = null;
                        if (preset.Ciphers is not null && preset.Ciphers.Count > 0) { }
                    }
                    internal int m_cipherSuite = Tls.CipherSuite.TLS_NULL_WITH_NULL_NULL;
                }
                """);
        TestSupport.write(root, "lib/tls.js", "var session = {\n  cipherSuite: null,\n};\n");
        // Étiquette de switch : la suite négociée est testée, pas activée (golang/crypto).
        TestSupport.write(root, "acme/autocert.go", """
                package autocert
                func supportsECDSA(suite uint16) bool {
                    switch suite {
                    case tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,
                        tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:
                        return true
                    }
                    return false
                }
                """);
        // En-têtes de clé sans clé : PEM construit par le code, constante d'un lecteur, documentation, assertion.
        TestSupport.write(root, "lessons/CryptoUtil.java", """
                class CryptoUtil {
                    String pem(java.security.PrivateKey privateKey) {
                        String encodedString = "-----BEGIN PRIVATE KEY-----\\n";
                        encodedString = encodedString + java.util.Base64.getEncoder().encodeToString(privateKey.getEncoded());
                        return encodedString;
                    }
                }
                """);
        TestSupport.write(root, "Keys/OpenSSH.php", """
                <?php
                function save($key) {
                    return "-----BEGIN OPENSSH PRIVATE KEY-----\\n" .
                           chunk_split(Strings::base64_encode($key), 70, "\\n") .
                           "-----END OPENSSH PRIVATE KEY-----\\n";
                }
                """);
        TestSupport.write(root, "serialization/ssh.py", """
                _SK_START = b"-----BEGIN OPENSSH PRIVATE KEY-----"
                _SK_END = b"-----END OPENSSH PRIVATE KEY-----"
                def check(pem):
                    assert pem.startswith("-----BEGIN ENCRYPTED PRIVATE KEY-----\\n")
                """);
        TestSupport.write(root, "ext/ossl_pkey.c", """
                /*
                 *     -----BEGIN EC PRIVATE KEY-----
                 *     [...]
                 */
                static int ossl_pkey(void) { return 0; }
                """);
        // Références Terraform/HCL et étiquettes : pas de valeur écrite (Vault).
        TestSupport.write(root, "enos/scenario.hcl", """
                variables {
                  vault_install_dir = local.vault_install_dir
                  vault_root_token  = step.create_primary_cluster.root_token
                }
                """);
        TestSupport.write(root, "ssh/path_config_ca.go", """
                package ssh
                const (
                    caPrivateKey = "ca_private_key"
                    exportTypeEncryptionKey = "encryption_key"
                )
                """);
        TestSupport.write(root, "maven/publish.sh", "#     https://ise-crypto:ACCESS_TOKEN@github.com/tink-crypto/tink-java \\\n");
        // Comparaison et importation (ruby/openssl, OWASP Benchmark).
        TestSupport.write(root, "lib/openssl/ssl.rb", """
                def post_connection_check
                  if self.verify_mode != OpenSSL::SSL::VERIFY_NONE
                    check
                  end
                end
                """);
        TestSupport.write(root, "helpers/Utils.java", """
                import org.apache.hc.client5.http.ssl.NoopHostnameVerifier;
                import org.apache.hc.client5.http.ssl.TrustSelfSignedStrategy;
                class Utils {
                }
                """);

        assertThat(detect(root)).extracting(f -> f.ruleId() + " " + f.file() + ":" + f.line()).isEmpty();
    }

    @Test
    void realUsesStayReportedAndTestDataIsLowered(@TempDir Path root) {
        TestSupport.write(root, "server/Client.java", """
                class Client {
                    void configure(javax.net.ssl.SSLSocket socket) {
                        socket.setEnabledCipherSuites(new String[] {"TLS_RSA_WITH_NULL_SHA"});
                    }
                    String token() {
                        String sessionToken = Long.toString(new java.util.Random().nextLong());
                        return sessionToken;
                    }
                    float jitter() {
                        float rand = new java.util.Random().nextFloat();
                        return rand;
                    }
                }
                """);
        TestSupport.write(root, "keys/server.key", "-----BEGIN RSA PRIVATE KEY-----\n"
                + "MIIEowIBAAKCAQEAu1SU1LfVLPHCozMxH2Mo4lgOEePzNm0tRgeLezV6ffAt0gun\n-----END RSA PRIVATE KEY-----\n");
        // Clé de test déclarée comme telle dans du code livré (Bitwarden) : signalée, mais comme donnée de test.
        TestSupport.write(root, "util/rsa_keys.rs", """
                const TEST_FAKE_RSA_KEY_0: &str = "-----BEGIN PRIVATE KEY-----
                MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKj
                -----END PRIVATE KEY-----";
                """);

        List<SecurityFinding> findings = detect(root);

        assertThat(findings).filteredOn(f -> f.file().equals("server/Client.java")).extracting(SecurityFinding::ruleId)
                .containsExactlyInAnyOrder("tls-cipher-list", "random-java-insecure", "random-java-general");
        assertThat(findings).filteredOn(f -> f.ruleId().equals("random-java-general")).singleElement()
                .satisfies(f -> assertThat(f.severity()).isEqualTo(Severity.LOW));
        assertThat(findings).filteredOn(f -> f.file().equals("keys/server.key")).singleElement()
                .satisfies(f -> assertThat(f.severity()).isEqualTo(Severity.HIGH));
        assertThat(findings).filteredOn(f -> f.file().equals("util/rsa_keys.rs")).singleElement().satisfies(f -> {
            assertThat(f.testCode()).isTrue();
            assertThat(f.severity()).isEqualTo(Severity.HIGH.lower());
        });
    }

    /** "password" écrit dans un test et transmis au code testé (spring-security) : une donnée de test. */
    @Test
    void aValueWrittenOnlyInTestsIsTestData(@TempDir Path root) {
        TestSupport.write(root, "crypto/src/main/java/Encryptor.java", """
                public class Encryptor {
                    public Encryptor(String password, byte[] salt) throws Exception {
                        new javax.crypto.spec.PBEKeySpec(password.toCharArray(), salt, 210000, 256);
                    }
                }
                """);
        TestSupport.write(root, "crypto/src/test/java/EncryptorTests.java", """
                public class EncryptorTests {
                    void roundTrip() throws Exception {
                        new Encryptor("Sup3rS3cretPass", new byte[16]);
                    }
                }
                """);

        assertThat(detect(root)).filteredOn(f -> f.file().equals("crypto/src/main/java/Encryptor.java")).isNotEmpty()
                .allSatisfy(f -> assertThat(f.testCode()).isTrue());
    }

    @Test
    void testConventionsOfEveryEcosystemAreRecognised() {
        var testPath = RULES.testPath();
        assertThat(List.of("lib/Crypto/SelfTest/Cipher/test_CBC.py", "src/foo/test_bar.py",
                "helper/serverconfig/config_test_helpers.go", "api/test-fixtures/keys/key.pem",
                "vectors/cryptography_vectors/pkcs12/cert.p12", "test_vectors/wycheproof/ecdh.json",
                "fuzz/client.c", "pkg/x/y_test.go", "src/test/java/A.java"))
                .allSatisfy(path -> assertThat(testPath.matcher(path).find()).as(path).isTrue());
        assertThat(List.of("src/latest/app.py", "attest/verify.go", "lib/contest.rb", "src/main/java/Testing.java"))
                .allSatisfy(path -> assertThat(testPath.matcher(path).find()).as(path).isFalse());
    }
}
