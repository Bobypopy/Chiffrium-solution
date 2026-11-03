package com.chiffrium.infrastructure.findings;

import com.chiffrium.TestSupport;
import com.chiffrium.application.port.CryptoDetector.DetectionContext;
import com.chiffrium.application.port.SbomGenerator.SbomResult;
import com.chiffrium.domain.model.SecurityFinding;
import com.chiffrium.domain.model.Severity;
import com.chiffrium.infrastructure.scan.FileSystemProjectScanner;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Code de bibliothèque (extraits de bc-java et de javax.mail) : un registre de suites, un exemple de
 * documentation ou un nom de propriété ne sont pas des faiblesses ; le même vocabulaire employé pour de bon l'est.
 */
class LibraryCodeFindingsTest {

    private static final FindingRuleLoader.FindingRuleSet RULES = new FindingRuleLoader(TestSupport.MAPPER).loadBuiltIn();

    private static List<SecurityFinding> detect(Path root) {
        DetectionContext context = new DetectionContext(root, new FileSystemProjectScanner(1_000_000).scan(root),
                SbomResult.empty());
        return new SecurityFindingDetector(RULES).detect(context).findings();
    }

    @Test
    void registriesDocumentationAndLabelsAreNotFindings(@TempDir Path root) {
        TestSupport.write(root, "tls/CipherSuite.java", """
                public class CipherSuite {
                    public static final int TLS_NULL_WITH_NULL_NULL = 0x0000;
                    public static final int TLS_RSA_EXPORT_WITH_RC4_40_MD5 = 0x0003;
                }
                """);
        TestSupport.write(root, "tls/cipher_suites.go", """
                package tls
                const (
                    TLS_RSA_WITH_RC4_128_SHA uint16 = 0x0005
                )
                """);
        TestSupport.write(root, "tls/ssl.h", "#define TLS_RSA_WITH_NULL_MD5 0x0001\n");
        TestSupport.write(root, "mail/SocketFetcher.java", """
                class SocketFetcher {
                    void configure(javax.net.ssl.SSLSocket socket, String[] ciphers) {
                        if (ciphers != null)
                            socket.setEnabledCipherSuites(ciphers);
                    }
                    void defaults(java.util.Collection<String> enabledSSLCipherSuites) {
                        if (enabledSSLCipherSuites == null) {
                            return;
                        }
                    }
                }
                """);
        // Algorithmes de chiffrement par blocs essayés par un test, pas des suites TLS (GMacTest).
        TestSupport.write(root, "prov/GMacTest.java", """
                class GMacTest {
                    String[] ciphers = new String[] { "AES", "NOEKEON", "Twofish", "SEED", "Serpent", "CAMELLIA" };
                }
                """);
        TestSupport.write(root, "mls/KeyScheduleEpoch.java", """
                class KeyScheduleEpoch {
                    public KeyScheduleEpoch(MlsCipherSuite suite, Secret initSecret, Secret exporterSecret) {
                    }
                }
                """);
        TestSupport.write(root, "openssl/JcaPrivateKeyReader.java", """
                /**
                 * <li>traditional (PKCS#1) RSA keys - {@code -----BEGIN RSA PRIVATE KEY-----} and their DER body;</li>
                 * <li>encrypted PKCS#8 ({@code -----BEGIN ENCRYPTED PRIVATE KEY-----} and DER</li>
                 */
                class JcaPrivateKeyReader {
                    private static final String HEADER = "-----BEGIN PRIVATE KEY-----";
                }
                """);
        TestSupport.write(root, "mail/URLName.java", """
                class URLName {
                    String[] tests = {
                        "protocol://userid:password@host:119/file",
                        "imap://jmr:secret@labyrinth//var/mail/jmr",
                    };
                }
                """);
        TestSupport.write(root, "util/Properties.java", """
                class Properties {
                    public static final String PKCS12_IGNORE_USELESS_PASSWD = "org.bouncycastle.pkcs12.ignore_useless_passwd";
                    public static final String CLIENT_EARLY_TRAFFIC_SECRET = "CLIENT_EARLY_TRAFFIC_SECRET";
                }
                """);
        TestSupport.write(root, "pkcs/PKCS8EncryptedPrivateKeyInfoBuilder.java", """
                class PKCS8EncryptedPrivateKeyInfoBuilder {
                    void build(java.io.OutputStream cOut, PrivateKeyInfo privateKeyInfo) throws Exception {
                        cOut.write(privateKeyInfo.getEncoded());
                    }
                }
                """);

        assertThat(detect(root)).extracting(f -> f.ruleId() + " " + f.file() + ":" + f.line()).isEmpty();
    }

    @Test
    void theSameVocabularyUsedForRealIsStillReported(@TempDir Path root) {
        TestSupport.write(root, "src/Client.java", """
                class Client {
                    void configure(javax.net.ssl.SSLSocket socket) {
                        socket.setEnabledCipherSuites(new String[] {"TLS_RSA_EXPORT_WITH_RC4_40_MD5"});
                    }
                    static final String KEY = "-----BEGIN RSA PRIVATE KEY-----\\n"
                            + "MIIEowIBAAKCAQEAu1SU1LfVLPHCozMxH2Mo4lgOEePzNm0tRgeLezV6ffAt0gun";
                    String database = "postgres://admin:Zq8vR2pL9wKx@db.internal:5432/app";
                    void export(java.io.OutputStream out, java.security.KeyPair pair) throws Exception {
                        out.write(pair.getPrivate().getEncoded());
                    }
                }
                """);
        TestSupport.write(root, "nginx.conf", "ssl_ciphers HIGH:!aNULL:EXPORT:RC4-SHA;\n");
        TestSupport.write(root, "client.py", "ctx.set_ciphers('NULL-SHA:AES128-GCM-SHA256')\n");
        TestSupport.write(root, "server.go", """
                package main
                var config = &tls.Config{CipherSuites: []uint16{tls.TLS_RSA_WITH_RC4_128_SHA}}
                """);

        List<SecurityFinding> findings = detect(root);

        assertThat(findings).extracting(SecurityFinding::ruleId).contains("secret-private-key",
                "secret-url-credentials", "key-java-unencrypted-export");
        // Suites activées dans le code et dans la configuration (EXPORT et NULL critiques, RC4 élevé).
        assertThat(findings).filteredOn(f -> f.ruleId().startsWith("tls-")).extracting(SecurityFinding::file)
                .containsExactlyInAnyOrder("src/Client.java", "nginx.conf", "client.py", "server.go");
        assertThat(findings).filteredOn(f -> f.ruleId().startsWith("tls-") && !f.file().equals("server.go"))
                .allSatisfy(f -> assertThat(f.severity()).isEqualTo(Severity.CRITICAL));
        assertThat(findings).filteredOn(f -> f.file().equals("server.go")).singleElement()
                .satisfies(f -> assertThat(f.severity()).isEqualTo(Severity.HIGH));
        assertThat(findings).filteredOn(f -> f.file().equals("nginx.conf")).singleElement()
                .satisfies(f -> assertThat(f.evidence()).contains("EXPORT", "RC4-SHA"));
    }
}
