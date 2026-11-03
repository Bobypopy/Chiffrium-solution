package com.chiffrium.infrastructure.rules;

import com.chiffrium.TestSupport;
import com.chiffrium.application.port.CryptoDetector.DetectionContext;
import com.chiffrium.application.port.SbomGenerator.SbomResult;
import com.chiffrium.domain.model.CryptoAsset;
import com.chiffrium.domain.model.SecurityFinding;
import com.chiffrium.infrastructure.findings.FindingRuleLoader;
import com.chiffrium.infrastructure.findings.SecurityFindingDetector;
import com.chiffrium.infrastructure.scan.FileSystemProjectScanner;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;

/** Configurations de plateformes : OpenSSL, IPsec, signatures XML (SAML), Android, iOS. */
class PlatformConfigDetectionTest {

    @TempDir
    static Path project;
    private static List<CryptoAsset> assets;
    private static List<SecurityFinding> findings;

    @BeforeAll
    static void analyze() {
        TestSupport.write(project, "etc/openssl.cnf", """
                [system_default_sect]
                MinProtocol = TLSv1
                CipherString = DEFAULT@SECLEVEL=1
                """);
        TestSupport.write(project, "etc/ipsec.conf", """
                conn office
                    ike=aes128-sha1-modp1024!
                    esp=3des-md5
                """);
        TestSupport.write(project, "etc/swanctl.conf", """
                connections {
                  pq {
                    proposals = aes256gcm16-prfsha384-x25519-mlkem768
                  }
                }
                """);
        TestSupport.write(project, "saml/idp-metadata.xml", """
                <ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
                <ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
                <xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#tripledes-cbc"/>
                <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
                """);
        TestSupport.write(project, "src/Saml.java", """
                class Saml {
                    static final String SIGNATURE = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
                }
                """);
        TestSupport.write(project, "android/AndroidManifest.xml", """
                <application android:usesCleartextTraffic="true" android:label="demo"/>
                """);
        TestSupport.write(project, "android/res/xml/network_security_config.xml", """
                <network-security-config>
                  <base-config>
                    <trust-anchors>
                      <certificates src="system"/>
                      <certificates src="user"/>
                    </trust-anchors>
                  </base-config>
                </network-security-config>
                """);
        TestSupport.write(project, "android-ok/res/xml/network_security_config.xml", """
                <network-security-config>
                  <base-config cleartextTrafficPermitted="false"/>
                  <debug-overrides>
                    <trust-anchors>
                      <certificates src="user"/>
                    </trust-anchors>
                  </debug-overrides>
                </network-security-config>
                """);
        TestSupport.write(project, "ios/Info.plist", """
                <key>NSAppTransportSecurity</key>
                <dict>
                  <key>NSAllowsArbitraryLoads</key>
                  <true/>
                  <key>NSExceptionMinimumTLSVersion</key>
                  <string>TLSv1.0</string>
                </dict>
                """);

        var scan = new FileSystemProjectScanner(1_000_000).scan(project);
        DetectionContext context = new DetectionContext(project, scan, SbomResult.empty());
        assets = new RuleBasedCryptoDetector(new RulePackLoader(TestSupport.MAPPER).loadBuiltIn(), TestSupport.ASSETS)
                .detect(context).assets();
        findings = new SecurityFindingDetector(new FindingRuleLoader(TestSupport.MAPPER).loadBuiltIn())
                .detect(context).findings();
    }

    private static Set<String> namesIn(String file) {
        return assets.stream().filter(a -> a.occurrences().stream().anyMatch(o -> o.file().equals(file)))
                .map(CryptoAsset::name).collect(Collectors.toSet());
    }

    private static Set<String> findingsIn(String file) {
        return findings.stream().filter(f -> f.file().equals(file)).map(SecurityFinding::ruleId)
                .collect(Collectors.toSet());
    }

    @Test
    void opensslSystemConfiguration() {
        assertThat(namesIn("etc/openssl.cnf")).contains("TLS 1.0");
        assertThat(findingsIn("etc/openssl.cnf")).contains("openssl-low-security-level");
    }

    @Test
    void ipsecProposalsAreSplitIntoAlgorithms() {
        assertThat(namesIn("etc/ipsec.conf")).contains("AES-128", "HMAC-SHA-1", "DH-1024", "3DES", "HMAC-MD5");
        assertThat(namesIn("etc/swanctl.conf")).contains("AES-256-GCM", "HMAC-SHA-384", "X25519", "ML-KEM-768");
    }

    @Test
    void xmlSignatureAndEncryptionAlgorithms() {
        assertThat(namesIn("saml/idp-metadata.xml")).contains("SHA-1withRSA", "SHA-1").anyMatch(n -> n.startsWith("3DES"));
        assertThat(namesIn("src/Saml.java")).contains("SHA-256withRSA");
    }

    @Test
    void androidNetworkSecurity() {
        assertThat(findingsIn("android/AndroidManifest.xml")).contains("android-cleartext-traffic");
        assertThat(findingsIn("android/res/xml/network_security_config.xml")).contains("android-user-certificates");
        // Certificats utilisateur réservés au débogage, trafic en clair refusé : rien à signaler.
        assertThat(findingsIn("android-ok/res/xml/network_security_config.xml")).isEmpty();
    }

    @Test
    void iosAppTransportSecurity() {
        assertThat(findingsIn("ios/Info.plist")).contains("ios-ats-insecure-loads", "ios-ats-old-tls");
    }
}
