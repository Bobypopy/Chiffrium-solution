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

/** Clés créées par le code : inventoriées là où elles naissent, dans chaque langage couvert. */
class GeneratedKeyDetectionTest {

    @TempDir
    static Path project;
    private static List<CryptoAsset> assets;

    @BeforeAll
    static void analyzeSamples() {
        TestSupport.write(project, "java/Keys.java", """
                public class Keys {
                    public KeyPair pair() throws Exception {
                        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
                        kpg.initialize(3072);
                        return kpg.generateKeyPair();
                    }
                    public SecretKey aes() throws Exception {
                        KeyGenerator kg = KeyGenerator.getInstance("AES");
                        kg.init(256);
                        return kg.generateKey();
                    }
                    public SecretKeySpec random() {
                        byte[] sessionKey = new byte[16];
                        new SecureRandom().nextBytes(sessionKey);
                        return new SecretKeySpec(sessionKey, "AES");
                    }
                    public SecretKeySpec fromFile(InputStream in) throws Exception {
                        byte[] key = new byte[32];
                        in.read(key);
                        return new SecretKeySpec(key, "AES");
                    }
                    public KeyFactory factory() throws Exception {
                        return KeyFactory.getInstance("RSA");
                    }
                }
                """);
        TestSupport.write(project, "python/keys.py", """
                import os
                from cryptography.hazmat.primitives.asymmetric import rsa
                from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
                from cryptography.hazmat.primitives.ciphers.aead import AESGCM
                from Crypto.Cipher import AES

                def pair():
                    return rsa.generate_private_key(public_exponent=65537, key_size=2048)

                def session():
                    key = AESGCM.generate_key(bit_length=128)
                    return AESGCM(key)

                def legacy(data):
                    aes_key = os.urandom(32)
                    iv = os.urandom(16)
                    return AES.new(aes_key, AES.MODE_GCM, nonce=iv).encrypt(data)

                def load(raw):
                    return Ed25519PrivateKey.from_private_bytes(raw)
                """);
        TestSupport.write(project, "js/keys.js", """
                const crypto = require('crypto');
                function pair() { return crypto.generateKeyPairSync('rsa', { modulusLength: 4096 }); }
                function mac() { return crypto.generateKeySync('hmac', { length: 256 }); }
                """);
        TestSupport.write(project, "go/keys.go", """
                package main
                func Keys() {
                    priv, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
                    key := make([]byte, 32)
                    rand.Read(key)
                    block, _ := aes.NewCipher(key)
                }
                """);
        TestSupport.write(project, "cs/Keys.cs", """
                public class Keys {
                    public void Pair() { using var rsa = RSA.Create(4096); }
                    public void Seal() {
                        byte[] key = RandomNumberGenerator.GetBytes(32);
                        using var gcm = new AesGcm(key, 16);
                    }
                }
                """);
        TestSupport.write(project, "c/keys.c", """
                EVP_PKEY *pair(void) { return EVP_RSA_gen(2048); }
                """);
        TestSupport.write(project, "php/keys.php", """
                <?php
                function pair() { return openssl_pkey_new(["private_key_bits" => 2048]); }
                """);
        TestSupport.write(project, "ruby/keys.rb", """
                def pair
                  OpenSSL::PKey::RSA.new(2048)
                end
                def load
                  OpenSSL::PKey::RSA.new(File.read("key.pem"))
                end
                """);
        TestSupport.write(project, "rust/keys.rs", """
                fn key() { let key = Aes256Gcm::generate_key(OsRng); }
                """);
        TestSupport.write(project, "swift/Keys.swift", """
                func pair() { let key = Curve25519.Signing.PrivateKey() }
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

    private static Set<String> algorithmsIn(String file) {
        return assets.stream()
                .filter(a -> a.material() == null)
                .filter(a -> a.occurrences().stream().anyMatch(o -> o.file().equals(file)))
                .map(CryptoAsset::name)
                .collect(Collectors.toSet());
    }

    @Test
    void javaKeyGeneratorsAndRandomBytesBecomeKeys() {
        assertThat(keysIn("java/Keys.java")).containsExactlyInAnyOrder(
                "Clé privée RSA-3072 générée (Keys.java)",
                "Clé secrète AES-256 générée (Keys.java)",
                "Clé secrète AES-128 générée (Keys.java)");
        // La taille tirée au hasard qualifie aussi l'algorithme ; un tampon lu dans un fichier n'est pas une génération.
        assertThat(algorithmsIn("java/Keys.java")).contains("AES-128", "AES");
    }

    @Test
    void pythonKeysIncludeSymmetricOnes() {
        assertThat(keysIn("python/keys.py")).containsExactlyInAnyOrder(
                "Clé privée RSA-2048 générée (keys.py)",
                "Clé secrète AES-128-GCM générée (keys.py)",
                "Clé secrète AES-256-GCM générée (keys.py)");
    }

    @Test
    void otherLanguages() {
        assertThat(keysIn("js/keys.js")).hasSize(2)
                .contains("Clé privée RSA-4096 générée (keys.js)")
                .anyMatch(name -> name.startsWith("Clé secrète HMAC"));
        assertThat(keysIn("go/keys.go")).hasSize(2)
                .contains("Clé secrète AES-256 générée (keys.go)")
                .anyMatch(name -> name.startsWith("Clé privée ECDSA"));
        assertThat(keysIn("cs/Keys.cs")).containsExactlyInAnyOrder(
                "Clé privée RSA-4096 générée (Keys.cs)", "Clé secrète AES-256-GCM générée (Keys.cs)");
        assertThat(keysIn("c/keys.c")).containsExactly("Clé privée RSA-2048 générée (keys.c)");
        assertThat(keysIn("php/keys.php")).containsExactly("Clé privée RSA-2048 générée (keys.php)");
        assertThat(keysIn("ruby/keys.rb")).containsExactly("Clé privée RSA-2048 générée (keys.rb)");
        assertThat(keysIn("rust/keys.rs")).containsExactly("Clé secrète AES-256-GCM générée (keys.rs)");
        assertThat(keysIn("swift/Keys.swift")).containsExactly("Clé privée Ed25519 générée (Keys.swift)");
    }

    @Test
    void generatedKeyKeepsItsLocation() {
        CryptoAsset key = assets.stream().filter(a -> a.name().equals("Clé privée RSA-3072 générée (Keys.java)"))
                .findFirst().orElseThrow();
        assertThat(key.occurrences()).singleElement().satisfies(o -> {
            assertThat(o.line()).isEqualTo(3);
            assertThat(o.function()).isEqualTo("Keys.pair");
        });
        assertThat(key.material().materialType()).isEqualTo("private-key");
    }
}
