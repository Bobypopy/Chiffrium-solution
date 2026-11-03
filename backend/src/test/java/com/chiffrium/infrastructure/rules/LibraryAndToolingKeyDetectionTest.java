package com.chiffrium.infrastructure.rules;

import com.chiffrium.TestSupport;
import com.chiffrium.application.port.CryptoDetector.DetectionContext;
import com.chiffrium.application.port.SbomGenerator.SbomResult;
import com.chiffrium.domain.model.CryptoAsset;
import com.chiffrium.infrastructure.scan.FileSystemProjectScanner;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Clés créées par des bibliothèques autres que l'API standard (post-quantique, NaCl, JOSE, Tink...) et par
 * l'outillage du dépôt (scripts, Terraform, cert-manager, KMS des fournisseurs cloud).
 */
class LibraryAndToolingKeyDetectionTest {

    @TempDir
    static Path project;
    private static List<CryptoAsset> assets;

    @BeforeAll
    static void analyzeSamples() {
        TestSupport.write(project, "java/Keys.java", """
                public class Keys {
                    KeysetHandle tink() throws Exception {
                        return KeysetHandle.generateNew(KeyTemplates.get("AES256_GCM"));
                    }
                    JWK nimbus() throws Exception {
                        return new RSAKeyGenerator(2048).generate();
                    }
                    SecretKey jjwt() {
                        return Jwts.SIG.HS256.key().build();
                    }
                    KeyPair legacyJjwt() {
                        return Keys.keyPairFor(SignatureAlgorithm.ES256);
                    }
                    String sign(SecretKey key) {
                        return Jwts.builder().signWith(key, Jwts.SIG.HS512).compact();
                    }
                    AsymmetricCipherKeyPair mlKem(SecureRandom random) {
                        MLKEMKeyPairGenerator generator = new MLKEMKeyPairGenerator();
                        generator.init(new MLKEMKeyGenerationParameters(random, MLKEMParameters.ml_kem_768));
                        return generator.generateKeyPair();
                    }
                }
                """);
        TestSupport.write(project, "python/keys.py", """
                import oqs
                from pqcrypto.kem.ml_kem_768 import generate_keypair, encrypt
                from nacl.public import PrivateKey

                def kem():
                    with oqs.KeyEncapsulation("ML-KEM-768") as kem:
                        return kem.generate_keypair()

                def box():
                    return PrivateKey.generate()

                def legacy():
                    return SigningKey.generate(curve=NIST384p)

                def web():
                    return jwk.JWK.generate(kty='EC', crv='P-256')

                def tink_key():
                    return tink.new_keyset_handle(aead.aead_key_templates.AES128_GCM)

                def vault(client):
                    return client.create_rsa_key("signing", size=3072)

                def peer(public_key):
                    with oqs.KeyEncapsulation("Kyber512") as kem:
                        return kem.encap_secret(public_key)
                """);
        TestSupport.write(project, "js/keys.js", """
                const keys = ml_kem768.keygen();
                const edSecret = ed25519.utils.randomPrivateKey();
                const pair = nacl.box.keyPair();
                const { privateKey } = await jose.generateKeyPair('ES384');
                const secret = await jose.generateSecret('A256GCM');
                const boxKey = sodium.crypto_secretbox_keygen();
                const aes = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 128 }, true, ['encrypt']);
                const vaultKey = await client.createEcKey('app', { curve: 'P-384' });
                """);
        TestSupport.write(project, "go/keys.go", """
                package main
                func Keys() {
                    pk, sk, _ := mlkem768.GenerateKeyPair(rand.Reader)
                    pub, priv, _ := box.GenerateKey(rand.Reader)
                    k, _ := ecdh.P384().GenerateKey(rand.Reader)
                }
                """);
        TestSupport.write(project, "cs/Keys.cs", """
                public class Keys {
                    public void Kem() { using var kem = MLKem.GenerateKey(MLKemAlgorithm.MLKem768); }
                    public void Rsa() {
                        var generator = new RsaKeyPairGenerator();
                        generator.Init(new KeyGenerationParameters(new SecureRandom(), 3072));
                    }
                }
                """);
        TestSupport.write(project, "c/keys.c", """
                void kem(void) {
                    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_1024);
                    OQS_KEM_keypair(kem, public_key, secret_key);
                }
                void box(void) { crypto_box_keypair(pk, sk); }
                """);
        TestSupport.write(project, "rust/keys.rs", """
                fn kem() { let (dk, ek) = MlKem768::generate(&mut rng); }
                fn ed() { let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng)?; }
                fn ec() { let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng)?; }
                """);
        TestSupport.write(project, "php/keys.php", """
                <?php
                function sign() { return sodium_crypto_sign_keypair(); }
                function rsa() { return RSA::createKey(4096); }
                """);
        TestSupport.write(project, "ruby/keys.rb", """
                def ed
                  OpenSSL::PKey.generate_key("ED25519")
                end
                def box
                  RbNaCl::PrivateKey.generate
                end
                """);
        TestSupport.write(project, "swift/Keys.swift", "func kem() { let key = MLKEM768.PrivateKey() }\n");
        TestSupport.write(project, "scripts/gen.sh", """
                openssl genrsa -out server.key 1024
                openssl req -x509 -newkey rsa:4096 -nodes -keyout k.pem -out c.pem -days 365
                openssl genpkey -algorithm ED25519 -aes-256-cbc -pass pass:Kq7vault9 -out ed.pem
                openssl ecparam -genkey -name prime256v1 -out ec.pem
                ssh-keygen -t ed25519 -N "" -f deploy_key
                ssh-keygen -t rsa -b 2048 -f k -N "$PASS"
                keytool -genkeypair -alias app -keyalg RSA -keysize 2048 -keystore app.jks -storepass changeit
                gpg --batch --quick-gen-key "Bot <bot@example.org>" rsa3072 sign never
                ssh-keygen -l -f deploy_key.pub
                """);
        TestSupport.write(project, "infra/main.tf", """
                resource "tls_private_key" "ca" {
                  algorithm   = "ECDSA"
                  ecdsa_curve = "P384"
                }
                resource "aws_kms_key" "signing" {
                  customer_master_key_spec = "RSA_3072"
                  key_usage                = "SIGN_VERIFY"
                }
                resource "google_kms_crypto_key" "k" {
                  version_template {
                    algorithm = "EC_SIGN_P256_SHA256"
                  }
                }
                resource "azurerm_key_vault_key" "app" {
                  key_type = "RSA-HSM"
                  key_size = 4096
                }
                """);
        TestSupport.write(project, "k8s/cert.yaml", """
                apiVersion: cert-manager.io/v1
                kind: Certificate
                spec:
                  secretName: web-tls
                  privateKey:
                    algorithm: ECDSA
                    size: 384
                """);
        TestSupport.write(project, "aws/stack.yaml", """
                Resources:
                  Key:
                    Type: AWS::KMS::Key
                    Properties:
                      KeySpec: ECC_SECG_P256K1
                """);

        var scan = new FileSystemProjectScanner(1_000_000).scan(project);
        assets = new RuleBasedCryptoDetector(new RulePackLoader(TestSupport.MAPPER).loadBuiltIn(), TestSupport.ASSETS)
                .detect(new DetectionContext(project, scan, SbomResult.empty())).assets();
    }

    private static Set<String> keysIn(String file) {
        return assets.stream()
                .filter(a -> a.material() != null && a.material().generated())
                .filter(a -> a.occurrences().stream().anyMatch(o -> o.file().equals(file)))
                .map(CryptoAsset::name)
                .collect(Collectors.toSet());
    }

    @Test
    void javaLibraries() {
        assertThat(keysIn("java/Keys.java")).containsExactlyInAnyOrder(
                "Clé secrète AES-256-GCM générée (Keys.java)",
                "Clé privée RSA-2048 générée (Keys.java)",
                "Clé secrète HMAC-SHA-256 générée (Keys.java)",
                "Clé privée ECDSA-P-256 générée (Keys.java)",
                "Clé privée ML-KEM-768 générée (Keys.java)");
    }

    @Test
    void pythonLibraries() {
        assertThat(keysIn("python/keys.py")).containsExactlyInAnyOrder(
                "Clé privée ML-KEM-768 générée (keys.py)",
                "Clé privée X25519 générée (keys.py)",
                "Clé privée ECDSA-P-384 générée (keys.py)",
                "Clé privée EC-P-256 générée (keys.py)",
                "Clé secrète AES-128-GCM générée (keys.py)",
                "Clé privée RSA-3072 générée (keys.py)");
    }

    @Test
    void javascriptLibraries() {
        assertThat(keysIn("js/keys.js")).containsExactlyInAnyOrder(
                "Clé privée ML-KEM-768 générée (keys.js)",
                "Clé privée Ed25519 générée (keys.js)",
                "Clé privée X25519 générée (keys.js)",
                "Clé privée ECDSA-P-384 générée (keys.js)",
                "Clé secrète AES-256-GCM générée (keys.js)",
                "Clé secrète Salsa20-Poly1305 générée (keys.js)",
                "Clé secrète AES-128-GCM générée (keys.js)",
                "Clé privée EC-P-384 générée (keys.js)");
    }

    @Test
    void otherLanguageLibraries() {
        assertThat(keysIn("go/keys.go")).containsExactlyInAnyOrder("Clé privée ML-KEM-768 générée (keys.go)",
                "Clé privée X25519 générée (keys.go)", "Clé privée ECDH-P-384 générée (keys.go)");
        assertThat(keysIn("cs/Keys.cs")).containsExactlyInAnyOrder("Clé privée ML-KEM-768 générée (Keys.cs)",
                "Clé privée RSA-3072 générée (Keys.cs)");
        assertThat(keysIn("c/keys.c")).containsExactlyInAnyOrder("Clé privée ML-KEM-1024 générée (keys.c)",
                "Clé privée X25519 générée (keys.c)");
        assertThat(keysIn("rust/keys.rs")).containsExactlyInAnyOrder("Clé privée ML-KEM-768 générée (keys.rs)",
                "Clé privée Ed25519 générée (keys.rs)", "Clé privée ECDSA-P-256 générée (keys.rs)");
        assertThat(keysIn("php/keys.php")).containsExactlyInAnyOrder("Clé privée Ed25519 générée (keys.php)",
                "Clé privée RSA-4096 générée (keys.php)");
        assertThat(keysIn("ruby/keys.rb")).containsExactlyInAnyOrder("Clé privée Ed25519 générée (keys.rb)",
                "Clé privée X25519 générée (keys.rb)");
        assertThat(keysIn("swift/Keys.swift")).containsExactly("Clé privée ML-KEM-768 générée (Keys.swift)");
    }

    @Test
    void commandLineTools() {
        assertThat(keysIn("scripts/gen.sh")).containsExactlyInAnyOrder(
                "Clé privée RSA-1024 générée (gen.sh)",
                "Clé privée RSA-4096 générée (gen.sh)",
                "Clé privée Ed25519 générée (gen.sh)",
                "Clé privée EC-P-256 générée (gen.sh)",
                "Clé privée RSA-2048 générée (gen.sh)",
                "Clé privée RSA-3072 générée (gen.sh)");
    }

    @Test
    void infrastructureAsCodeAndKms() {
        assertThat(keysIn("infra/main.tf")).containsExactlyInAnyOrder(
                "Clé privée ECDSA-P-384 générée (main.tf)",
                "Clé privée RSA-3072 générée (main.tf)",
                "Clé privée ECDSA-P-256 générée (main.tf)",
                "Clé privée RSA-4096 générée (main.tf)");
        assertThat(keysIn("k8s/cert.yaml")).containsExactly("Clé privée ECDSA-384 générée (cert.yaml)");
        assertThat(keysIn("aws/stack.yaml")).containsExactly("Clé privée EC-secp256k1 générée (stack.yaml)");
    }
}
