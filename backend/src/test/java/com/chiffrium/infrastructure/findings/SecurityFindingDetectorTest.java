package com.chiffrium.infrastructure.findings;

import com.chiffrium.TestSupport;
import com.chiffrium.application.port.CryptoDetector.DetectionContext;
import com.chiffrium.application.port.SbomGenerator.SbomResult;
import com.chiffrium.domain.model.FindingCategory;
import com.chiffrium.domain.model.SecurityFinding;
import com.chiffrium.domain.model.Severity;
import com.chiffrium.infrastructure.scan.FileSystemProjectScanner;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class SecurityFindingDetectorTest {

    private static final long MAX_FILE_BYTES = 1_000_000;
    private static final FindingRuleLoader.FindingRuleSet RULES = new FindingRuleLoader(TestSupport.MAPPER).loadBuiltIn();
    /** Jeton au format GitHub, fabriqué pour le test (aucune valeur réelle). */
    private static final String FAKE_GITHUB_TOKEN = "ghp_" + "aB3dE5fG7hJ9kL1mN3pQ5rS7tU9vW1xY3zA5";

    private static List<SecurityFinding> detect(Path root) {
        DetectionContext context = new DetectionContext(root, new FileSystemProjectScanner(MAX_FILE_BYTES).scan(root),
                SbomResult.empty());
        return new SecurityFindingDetector(RULES).detect(context).findings();
    }

    private static List<String> ruleIds(List<SecurityFinding> findings) {
        return findings.stream().map(SecurityFinding::ruleId).toList();
    }

    @Test
    void detectsSecretsAndNeverCopiesThemInTheReport(@TempDir Path root) {
        TestSupport.write(root, "src/Config.java", """
                class Config {
                    static final String TOKEN = "%s";
                    String dbPassword = "Zq8!vR2#pL9w";
                }
                """.formatted(FAKE_GITHUB_TOKEN));
        TestSupport.write(root, "deploy/app.yml", "db:\n  password: Hx7kQ2mP9vLr\n  url: https://db.internal/x\n");

        List<SecurityFinding> findings = detect(root);

        assertThat(ruleIds(findings)).contains("secret-github-token", "secret-generic-assignment",
                "secret-config-assignment");
        assertThat(findings).allSatisfy(f -> {
            assertThat(f.snippet()).doesNotContain(FAKE_GITHUB_TOKEN).doesNotContain("Zq8!vR2#pL9w")
                    .doesNotContain("Hx7kQ2mP9vLr");
            assertThat(f.evidence()).doesNotContain(FAKE_GITHUB_TOKEN);
        });
        assertThat(findings.get(0).severity()).isEqualTo(Severity.CRITICAL);
    }

    @Test
    void ignoresPlaceholdersEnvironmentLookupsLowEntropyAndSuppressedLines(@TempDir Path root) {
        TestSupport.write(root, "src/Config.java", """
                class Config {
                    String a = System.getenv("DB_PASSWORD");
                    String password = "changeme-please";
                    String secret = "aaaaaaaaaaaa";
                    String apiKey = "Zq8!vR2#pL9w"; // chiffrium:ignore
                }
                """);
        TestSupport.write(root, "app.yml", "password: ${DB_PASSWORD}\ntoken_url: https://auth.example.org/oauth\n");
        // Clé YAML sans valeur : la ligne suivante n'est pas sa valeur.
        TestSupport.write(root, "ci.yml", "jobs:\n  release:\n    secrets:\n      regcredProdEu1\n");

        assertThat(detect(root)).isEmpty();
    }

    @Test
    void detectsDisabledCertificateValidationAcrossLanguages(@TempDir Path root) {
        TestSupport.write(root, "a.py", "requests.get(url, verify=False)\n");
        TestSupport.write(root, "b.js", "https.request({ host, rejectUnauthorized: false })\n");
        TestSupport.write(root, "c.go", "cfg := &tls.Config{InsecureSkipVerify: true}\n");
        TestSupport.write(root, "D.java", """
                class D implements X509TrustManager {
                    public void checkServerTrusted(X509Certificate[] c, String a) {}
                }
                """);
        TestSupport.write(root, "e.cs", "handler.ServerCertificateCustomValidationCallback = (m, c, ch, e) => true;\n");
        TestSupport.write(root, "install.sh", "curl -k https://example.org/install | sh\n");

        List<SecurityFinding> findings = detect(root);

        assertThat(ruleIds(findings)).contains("tls-python-verify-false", "tls-node-reject-unauthorized",
                "tls-go-insecure-skip-verify", "tls-java-trust-all-manager", "tls-csharp-accept-any", "tls-cli-insecure");
        assertThat(findings).extracting(SecurityFinding::category).containsOnly(FindingCategory.CERTIFICATE_VALIDATION);
    }

    @Test
    void evaluatesTlsCipherSuitesAndSshAlgorithms(@TempDir Path root) {
        TestSupport.write(root, "nginx.conf", """
                ssl_ciphers 'ECDHE-RSA-AES128-GCM-SHA256:RC4-SHA:DES-CBC3-SHA:!aNULL';
                """);
        TestSupport.write(root, "strong.conf", "ssl_ciphers 'ECDHE-ECDSA-AES256-GCM-SHA384:HIGH:!aNULL:!MD5';\n");
        TestSupport.write(root, "sshd_config", "Ciphers aes256-gcm@openssh.com,3des-cbc\nMACs hmac-sha2-256,hmac-md5\n");
        TestSupport.write(root, "Tls.java", "String s = \"TLS_RSA_WITH_AES_128_CBC_SHA\";\n");

        List<SecurityFinding> findings = detect(root);

        SecurityFinding nginx = findings.stream().filter(f -> f.file().equals("nginx.conf")).findFirst().orElseThrow();
        assertThat(nginx.severity()).isEqualTo(Severity.HIGH);
        assertThat(nginx.evidence()).contains("RC4-SHA", "DES-CBC3-SHA").doesNotContain("ECDHE-RSA-AES128-GCM");
        assertThat(findings).noneMatch(f -> f.file().equals("strong.conf"));
        assertThat(findings.stream().filter(f -> f.file().equals("sshd_config")).count()).isEqualTo(2);
        assertThat(findings).anyMatch(f -> f.ruleId().equals("tls-iana-suite") && f.evidence().contains("TLS_RSA_WITH"));
    }

    @Test
    void detectsWeakRandomHardcodedKeysAndWeakKdf(@TempDir Path root) {
        TestSupport.write(root, "src/Crypto.java", """
                class Crypto {
                    String token = Long.toString(new Random().nextLong());
                    int unrelated = new Random().nextInt(6);
                    SecretKeySpec key = new SecretKeySpec("0123456789abcdef".getBytes(), "AES");
                    IvParameterSpec iv = new IvParameterSpec(new byte[16]);
                    PBEKeySpec spec = new PBEKeySpec(pwd, salt, 1000, 256);
                    PBEKeySpec strong = new PBEKeySpec(pwd, salt, 600000, 256);
                }
                """);
        TestSupport.write(root, "jdk/java.security", "jdk.tls.disabledAlgorithms=SSLv3, RC4, DES, NULL, anon\n");

        List<SecurityFinding> findings = detect(root);

        assertThat(ruleIds(findings)).contains("random-java-insecure", "key-java-literal", "iv-java-static",
                "kdf-java-pbkdf2-iterations", "jdk-tls-disabled-algorithms");
        assertThat(findings.stream().filter(f -> f.ruleId().equals("random-java-insecure")).count()).isEqualTo(1);
        assertThat(findings.stream().filter(f -> f.ruleId().equals("kdf-java-pbkdf2-iterations")).count()).isEqualTo(1);
        SecurityFinding jdk = findings.stream().filter(f -> f.ruleId().equals("jdk-tls-disabled-algorithms"))
                .findFirst().orElseThrow();
        assertThat(jdk.evidence()).contains("TLSv1", "TLSv1.1", "3DES_EDE_CBC").doesNotContain("SSLv3");
        assertThat(findings).allSatisfy(f -> assertThat(f.snippet()).doesNotContain("0123456789abcdef"));
    }

    @Test
    void lowersSeverityInTestCodeAndFlagsCommittedKeystores(@TempDir Path root) {
        TestSupport.write(root, "src/test/java/FooTest.java", "requests = 0; // verify=False\nString t = \"%s\";\n"
                .formatted(FAKE_GITHUB_TOKEN));
        TestSupport.write(root, "certs/server.p12", "binaire");

        List<SecurityFinding> findings = detect(root);

        SecurityFinding token = findings.stream().filter(f -> f.ruleId().equals("secret-github-token")).findFirst()
                .orElseThrow();
        assertThat(token.testCode()).isTrue();
        assertThat(token.severity()).isEqualTo(Severity.HIGH);
        assertThat(ruleIds(findings)).contains("secret-keystore-file");
    }

    @Test
    void cipherSuitePolicyIgnoresExclusionsAndDirectives() {
        CipherSuitePolicy policy = RULES.cipherSuites();
        assertThat(policy.weakSuites("HIGH:!aNULL:!eNULL:!RC4:@STRENGTH")).isEmpty();
        assertThat(policy.weakSuites("TLS_AES_128_GCM_SHA256 TLS_CHACHA20_POLY1305_SHA256")).isEmpty();
        assertThat(policy.evaluate("TLS_ECDH_anon_WITH_AES_128_CBC_SHA")).get()
                .extracting(CipherSuitePolicy.Verdict::severity).isEqualTo(Severity.CRITICAL);
        assertThat(policy.evaluate("AES128-SHA")).get()
                .extracting(CipherSuitePolicy.Verdict::severity).isEqualTo(Severity.MEDIUM);
    }

    @Test
    void detectsKeysPassedThroughAConstantAndWeakKdfSettings(@TempDir Path root) {
        // Cas le plus courant en vrai : la clé est déclarée une fois puis réutilisée plus loin.
        TestSupport.write(root, "src/Crypto.java", """
                class Crypto {
                    private static final String CLE = "8f2b91c4d7e05a63";

                    byte[] chiffrer(byte[] donnees) throws Exception {
                        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(CLE.getBytes(), "AES"));
                        return cipher.doFinal(donnees);
                    }
                }
                """);
        TestSupport.write(root, "app/ciphers.py", """
                CLE_SECRETE = "7c1e9ab35d2f4680"

                def chiffrer(donnees):
                    return AES.new(CLE_SECRETE).encrypt(donnees)
                """);
        TestSupport.write(root, "conf/application.properties",
                "pbkdf2.iterations=1000\nserver.port=8080\n");

        List<SecurityFinding> findings = detect(root);

        assertThat(ruleIds(findings))
                .contains("key-java-constant", "key-python-constant", "kdf-config-pbkdf2-iterations");
        // Le secret ne doit jamais ressortir en clair, même détecté à distance de son usage.
        assertThat(findings).allSatisfy(f -> assertThat(f.snippet() + " " + f.evidence())
                .doesNotContain("8f2b91c4d7e05a63").doesNotContain("7c1e9ab35d2f4680"));
        // Un réglage correct ne doit rien déclencher.
        TestSupport.write(root, "conf/application.properties",
                "pbkdf2.iterations=600000\nserver.port=8080\n");
        assertThat(ruleIds(detect(root))).doesNotContain("kdf-config-pbkdf2-iterations");
    }

    @Test
    void flagsPrivateKeysExportedInClearAndHardcodedKeyPasswords(@TempDir Path root) {
        TestSupport.write(root, "src/Store.java", """
                class Store {
                    void save(KeyPair kp, Path p, KeyStore ks, OutputStream out) throws Exception {
                        Files.write(p, kp.getPrivate().getEncoded());
                        ks.store(out, "Kq7#vault".toCharArray());
                        ks.store(out, password);
                    }
                }
                """);
        TestSupport.write(root, "app/keys.py", """
                def export(private_key):
                    clear = private_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
                    safe = private_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, BestAvailableEncryption(pw))
                    other = load_pem_private_key(data, b"Kq7#vault")
                """);
        TestSupport.write(root, "app/keys.js", """
                const clear = crypto.generateKeyPairSync('rsa', { privateKeyEncoding: { type: 'pkcs8', format: 'pem' } });
                const safe = crypto.generateKeyPairSync('rsa', {
                  privateKeyEncoding: { type: 'pkcs8', format: 'pem', cipher: 'aes-256-cbc', passphrase: secret } });
                """);
        TestSupport.write(root, "app/keys.go", """
                func save(k *rsa.PrivateKey) {
                    pem.Encode(f, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)})
                    pfx, _ := pkcs12.Modern.Encode(k, cert, nil, "Kq7#vault")
                }
                """);
        TestSupport.write(root, "app/keys.c", """
                void save(FILE *f, EVP_PKEY *k) {
                    PEM_write_PrivateKey(f, k, NULL, NULL, 0, NULL, NULL);
                    PEM_write_PrivateKey(f, k, EVP_aes_256_cbc(), NULL, 0, NULL, pass);
                }
                """);
        TestSupport.write(root, "app/Keys.cs", """
                class Keys {
                    void Save(RSA rsa) {
                        var clear = rsa.ExportPkcs8PrivateKey();
                        var safe = rsa.ExportEncryptedPkcs8PrivateKey(pwd, parameters);
                        var cert = new X509Certificate2("cert.pfx", "Kq7#vault");
                    }
                }
                """);
        TestSupport.write(root, "app/keys.php", """
                <?php
                openssl_pkey_export($res, $pem);
                openssl_pkey_export($res, $pem, $passphrase);
                $k = openssl_pkey_get_private('file://key.pem', 'Kq7#vault');
                """);
        TestSupport.write(root, "app/keys.rb", "pem = private_key.to_pem\nsafe = private_key.export(cipher, pass)\n");
        TestSupport.write(root, "app/keys.rs", "let pem = key.to_pkcs8_pem(LineEnding::LF)?;\n");

        List<SecurityFinding> findings = detect(root);

        assertThat(findings).filteredOn(f -> f.ruleId().endsWith("-unencrypted-export"))
                .extracting(f -> f.file() + ":" + f.line())
                .containsExactlyInAnyOrder("src/Store.java:3", "app/keys.py:2", "app/keys.js:1", "app/keys.go:2",
                        "app/keys.c:2", "app/Keys.cs:3", "app/keys.php:2", "app/keys.rb:1", "app/keys.rs:1");
        assertThat(findings).filteredOn(f -> f.ruleId().startsWith("secret-") && f.ruleId().endsWith("-password"))
                .extracting(f -> f.file() + ":" + f.line())
                .containsExactlyInAnyOrder("src/Store.java:4", "app/keys.py:4", "app/keys.go:3", "app/Keys.cs:5",
                        "app/keys.php:4");
        assertThat(findings).allSatisfy(f -> assertThat(f.snippet() + " " + f.evidence()).doesNotContain("Kq7#vault"));
    }

    @Test
    void flagsKeysGeneratedInClearAndPasswordsOnTheCommandLine(@TempDir Path root) {
        TestSupport.write(root, "scripts/gen.sh", """
                openssl genrsa -out server.key 2048
                openssl req -x509 -newkey rsa:4096 -nodes -keyout k.pem -out c.pem
                openssl genpkey -algorithm ED25519 -aes-256-cbc -pass pass:Kq7vault9 -out ed.pem
                ssh-keygen -t ed25519 -N "" -f deploy_key
                ssh-keygen -t rsa -b 4096 -f k -N "$PASS"
                keytool -genkeypair -keyalg RSA -keystore app.jks -storepass changeit
                keytool -genkeypair -keyalg RSA -keystore app.jks -storepass:env STORE_PASS
                openssl genrsa -aes256 -passout env:KEY_PASS -out safe.key 4096
                """);

        List<SecurityFinding> findings = detect(root);

        assertThat(findings).filteredOn(f -> f.ruleId().equals("key-cli-unencrypted-export"))
                .extracting(SecurityFinding::line).containsExactlyInAnyOrder(1, 2, 4);
        assertThat(findings).filteredOn(f -> f.ruleId().equals("secret-cli-key-password"))
                .extracting(SecurityFinding::line).containsExactlyInAnyOrder(3, 6);
        assertThat(findings).allSatisfy(f -> assertThat(f.snippet() + " " + f.evidence())
                .doesNotContain("Kq7vault9").doesNotContain("changeit"));
    }
}
