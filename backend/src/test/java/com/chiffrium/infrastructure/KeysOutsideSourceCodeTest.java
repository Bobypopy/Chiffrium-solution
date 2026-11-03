package com.chiffrium.infrastructure;

import com.chiffrium.TestSupport;
import com.chiffrium.application.port.CryptoDetector.DetectionContext;
import com.chiffrium.application.port.SbomGenerator.SbomResult;
import com.chiffrium.domain.model.CryptoAsset;
import com.chiffrium.domain.model.PolicyStatus;
import com.chiffrium.domain.model.SecurityFinding;
import com.chiffrium.domain.model.Severity;
import com.chiffrium.domain.policy.PolicyEvaluator;
import com.chiffrium.infrastructure.findings.FindingRuleLoader;
import com.chiffrium.infrastructure.findings.SecurityFindingDetector;
import com.chiffrium.infrastructure.material.MaterialDetector;
import com.chiffrium.infrastructure.rules.RuleBasedCryptoDetector;
import com.chiffrium.infrastructure.rules.RulePackLoader;
import com.chiffrium.infrastructure.scan.FileSystemProjectScanner;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPairGenerator;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Clés hors du code source : fichiers de données (JSON, état Terraform, kubeconfig), PEM encodé en Base64, JWK,
 * fichier de clé illisible, génération dont l'algorithme est inconnu, outillage (PowerShell, Ansible, Vault).
 */
class KeysOutsideSourceCodeTest {

    @TempDir
    static Path project;
    private static List<CryptoAsset> assets;
    private static List<SecurityFinding> findings;

    @BeforeAll
    static void analyze() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        String der = Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII))
                .encodeToString(generator.generateKeyPair().getPrivate().getEncoded());
        String pem = "-----BEGIN PRIVATE KEY-----\n" + der + "\n-----END PRIVATE KEY-----\n";

        TestSupport.write(project, "deploy/service-account.json", """
                {
                  "type": "service_account",
                  "private_key": "%s",
                  "client_email": "bot@project.iam.gserviceaccount.com"
                }
                """.formatted(pem.replace("\n", "\\n")));
        TestSupport.write(project, "k8s/tls-secret.yaml", """
                apiVersion: v1
                kind: Secret
                type: kubernetes.io/tls
                data:
                  tls.key: %s
                """.formatted(Base64.getEncoder().encodeToString(pem.getBytes(StandardCharsets.US_ASCII))));
        TestSupport.write(project, "auth/jwks.json", """
                {"keys": [
                  {"kty": "RSA", "kid": "1", "n": "%s", "e": "AQAB", "d": "c2VjcmV0LWV4cG9uZW50LXZhbHVlLWZvci10ZXN0cw"},
                  {"kty": "EC", "crv": "P-256", "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU", "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"}
                ]}
                """.formatted("q".repeat(342)));
        TestSupport.write(project, "infra/terraform.tfstate", "{\"version\": 4, \"resources\": []}\n");
        Files.createDirectories(project.resolve("keys"));
        Files.write(project.resolve("keys/legacy.key"), new byte[]{0x30, (byte) 0x82, 0x04, (byte) 0xa3, 0x02, 0x01});
        Files.write(project.resolve("keys/peer.pub"), new byte[]{0x30, (byte) 0x82, 0x01, 0x22});
        TestSupport.write(project, "src/Dynamic.java", """
                public class Dynamic {
                    KeyPair pair(String algorithm) throws Exception {
                        return KeyPairGenerator.getInstance(algorithm).generateKeyPair();
                    }
                    KeysetHandle tink() throws Exception {
                        return KeysetHandle.generateNew(KeyTemplates.get("HOMEMADE_CIPHER"));
                    }
                }
                """);
        TestSupport.write(project, "ops/cert.ps1", """
                New-SelfSignedCertificate -DnsName app.local -KeyAlgorithm ECDSA_nistP384 `
                  -CertStoreLocation Cert:\\LocalMachine\\My
                New-SelfSignedCertificate -DnsName legacy.local -KeyLength 1024
                """);
        TestSupport.write(project, "ops/playbook.yml", """
                - name: Clé du serveur
                  community.crypto.openssl_privatekey:
                    path: /etc/ssl/private/server.key
                    type: ECC
                    curve: secp384r1
                - name: Clé de déploiement
                  community.crypto.openssh_keypair:
                    path: /home/deploy/.ssh/id
                    size: 4096
                """);
        TestSupport.write(project, "ops/vault.sh", """
                vault write -f transit/keys/payments type=rsa-4096
                vault write -f transit/keys/sessions
                vault write transit/keys/sessions/rotate
                """);
        TestSupport.write(project, "infra/vault.tf", """
                resource "vault_transit_secret_backend_key" "signing" {
                  backend = "transit"
                  name    = "signing"
                  type    = "ecdsa-p256"
                }
                """);
        TestSupport.write(project, "infra/index.ts", """
                const key = new tls.PrivateKey("ca", { algorithm: "RSA", rsaBits: 3072 });
                """);

        var scan = new FileSystemProjectScanner(1_000_000).scan(project);
        DetectionContext context = new DetectionContext(project, scan, SbomResult.empty());
        PolicyEvaluator evaluator = new PolicyEvaluator(TestSupport.CATALOG, TestSupport.clockAt(2026));
        List<CryptoAsset> detected = new ArrayList<>(new MaterialDetector(TestSupport.ASSETS).detect(context).assets());
        detected.addAll(new RuleBasedCryptoDetector(new RulePackLoader(TestSupport.MAPPER).loadBuiltIn(),
                TestSupport.ASSETS).detect(context).assets());
        assets = detected.stream().map(evaluator::evaluate).toList();
        findings = new SecurityFindingDetector(new FindingRuleLoader(TestSupport.MAPPER).loadBuiltIn())
                .detect(context).findings();
    }

    private static Set<String> namesIn(String file) {
        return assets.stream()
                .filter(a -> a.material() != null)
                .filter(a -> a.occurrences().stream().anyMatch(o -> o.file().equals(file)))
                .map(CryptoAsset::name)
                .collect(Collectors.toSet());
    }

    private static CryptoAsset named(String name) {
        return assets.stream().filter(a -> a.name().equals(name)).findFirst()
                .orElseThrow(() -> new AssertionError(name + " absent : " + assets.stream().map(CryptoAsset::name).toList()));
    }

    private static Set<String> findingRulesIn(String file) {
        return findings.stream().filter(f -> f.file().equals(file)).map(SecurityFinding::ruleId)
                .collect(Collectors.toSet());
    }

    @Test
    void keysInDataFilesAreFound() {
        assertThat(namesIn("deploy/service-account.json")).containsExactly("Clé privée RSA-2048 (service-account.json)");
        assertThat(namesIn("k8s/tls-secret.yaml")).containsExactly("Clé privée RSA-2048 (tls-secret.yaml)");
        assertThat(named("Clé privée RSA-2048 (tls-secret.yaml)").occurrences().get(0).line()).isEqualTo(5);
        assertThat(namesIn("auth/jwks.json"))
                .containsExactlyInAnyOrder("Clé privée RSA-2048 (jwks.json)", "Clé publique EC-P-256 (jwks.json#1)");
        assertThat(named("Clé privée RSA-2048 (jwks.json)").verdict().severity()).isEqualTo(Severity.CRITICAL);
    }

    @Test
    void unreadableKeyFileIsNoLongerTakenForAPublicKey() {
        CryptoAsset unknown = named("Clé non identifiée (legacy.key)");
        assertThat(unknown.verdict().status()).isEqualTo(PolicyStatus.UNKNOWN);
        assertThat(unknown.verdict().severity()).isEqualTo(Severity.MEDIUM);
        assertThat(named("Clé publique (peer.pub)").verdict().status()).isEqualTo(PolicyStatus.ACCEPTABLE);
    }

    @Test
    void keysWithAnUnknownAlgorithmAreStillInventoried() {
        assertThat(namesIn("src/Dynamic.java")).containsExactlyInAnyOrder(
                "Clé privée générée, algorithme non déterminé (Dynamic.java)",
                "Clé générée, algorithme non déterminé (Dynamic.java)");
        assertThat(assets).filteredOn(a -> a.name().contains("algorithme non déterminé"))
                .allSatisfy(a -> assertThat(a.verdict().status()).isEqualTo(PolicyStatus.UNKNOWN));
    }

    @Test
    void moreTooling() {
        assertThat(namesIn("ops/cert.ps1")).containsExactlyInAnyOrder(
                "Clé privée ECDSA-P-384 générée (cert.ps1)", "Clé privée RSA-1024 générée (cert.ps1)");
        assertThat(namesIn("ops/playbook.yml")).containsExactlyInAnyOrder(
                "Clé privée EC-P-384 générée (playbook.yml)", "Clé privée RSA-4096 générée (playbook.yml)");
        assertThat(namesIn("ops/vault.sh")).containsExactlyInAnyOrder(
                "Clé privée RSA-4096 générée (vault.sh)", "Clé secrète AES-256-GCM générée (vault.sh)");
        assertThat(namesIn("infra/vault.tf")).containsExactly("Clé privée ECDSA-P-256 générée (vault.tf)");
        assertThat(namesIn("infra/index.ts")).containsExactly("Clé privée RSA-3072 générée (index.ts)");
    }

    @Test
    void findingsOnDataFiles() {
        assertThat(findingRulesIn("deploy/service-account.json")).contains("secret-private-key");
        assertThat(findingRulesIn("k8s/tls-secret.yaml")).contains("secret-private-key-base64");
        assertThat(findingRulesIn("auth/jwks.json")).containsExactly("secret-jwk-private");
        assertThat(findingRulesIn("infra/terraform.tfstate")).contains("secret-terraform-state");
        assertThat(findings).allSatisfy(f -> assertThat(String.valueOf(f.snippet()) + f.evidence())
                .doesNotContain("c2VjcmV0LWV4cG9uZW50"));
    }
}
