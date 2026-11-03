package com.chiffrium.infrastructure.rules;

import com.chiffrium.TestSupport;
import com.chiffrium.application.port.CryptoDetector.DetectionContext;
import com.chiffrium.application.port.CryptoDetector.DetectionResult;
import com.chiffrium.application.port.CryptoDetector.FileFlow;
import com.chiffrium.application.port.SbomGenerator.SbomResult;
import com.chiffrium.domain.model.CryptoAsset;
import com.chiffrium.domain.model.CryptoFunction;
import com.chiffrium.domain.model.Occurrence;
import com.chiffrium.infrastructure.scan.FileSystemProjectScanner;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;

class RuleBasedCryptoDetectorTest {

    private static final long MAX_FILE_BYTES = 1_000_000;

    @TempDir
    static Path project;
    private static DetectionResult result;

    @BeforeAll
    static void analyzeSamples() {
        TestSupport.write(project, "java/Crypto.java", """
                package demo;
                import javax.crypto.Cipher;
                public class Crypto {
                    private static final String TRANSFORMATION = "AES/GCM/NoPadding";
                    // Cipher.getInstance("DES") est un commentaire : ignoré
                    public byte[] encrypt(byte[] data) throws Exception {
                        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
                        return cipher.doFinal(data);
                    }
                    public java.security.KeyPair keys() throws Exception {
                        java.security.KeyPairGenerator kpg = java.security.KeyPairGenerator.getInstance("RSA");
                        kpg.initialize(1024);
                        return kpg.generateKeyPair();
                    }
                    public byte[] legacy(byte[] d) throws Exception {
                        return java.security.MessageDigest.getInstance("MD5").digest(d);
                    }
                    public void dynamic(String algo) throws Exception {
                        Cipher.getInstance(algo);
                    }
                    public void save(byte[] k) throws Exception {
                        try (var out = new java.io.FileOutputStream("private.pem")) { out.write(k); }
                    }
                }
                """);
        TestSupport.write(project, "kotlin/Hash.kt", """
                fun sha(bytes: ByteArray): ByteArray = java.security.MessageDigest.getInstance("SHA-512").digest(bytes)
                """);
        TestSupport.write(project, "python/crypto.py", """
                import hashlib, hmac
                from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
                from cryptography.hazmat.primitives.asymmetric import rsa, ec

                def digest(data):
                    return hashlib.sha1(data).hexdigest()

                def sign(key, data):
                    return hmac.new(key, data, hashlib.sha256).digest()

                def encrypt(key, iv, data):
                    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
                    return cipher.encryptor().update(data)

                def keys():
                    private = rsa.generate_private_key(public_exponent=65537, key_size=4096)
                    other = ec.generate_private_key(ec.SECP384R1())
                    with open("server.key", "wb") as f:
                        f.write(b"")
                """);
        TestSupport.write(project, "js/crypto.js", """
                const crypto = require('crypto');
                function hash(data) { return crypto.createHash('md5').update(data).digest('hex'); }
                const ALGO = 'aes-256-cbc';
                function encrypt(key, iv, text) {
                  const cipher = crypto.createCipheriv(ALGO, key, iv);
                  return cipher.update(text);
                }
                const { publicKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
                jwt.sign(payload, secret, { algorithm: 'HS256' });
                """);
        TestSupport.write(project, "go/main.go", """
                package main
                import ("crypto/aes"; "crypto/cipher"; "crypto/md5"; "crypto/rsa"; "crypto/rand"; "crypto/tls")
                func Encrypt(key []byte) {
                    block, _ := aes.NewCipher(key)
                    gcm, _ := cipher.NewGCM(block)
                    _ = gcm
                }
                func Hash(b []byte) { md5.Sum(b) }
                func Keys() { rsa.GenerateKey(rand.Reader, 2048) }
                var cfg = &tls.Config{MinVersion: tls.VersionTLS10}
                """);
        TestSupport.write(project, "cs/Crypto.cs", """
                using System.Security.Cryptography;
                public class Crypto {
                    public byte[] Hash(byte[] d) { using var sha = SHA1.Create(); return sha.ComputeHash(d); }
                    public void Enc() {
                        using var aes = Aes.Create();
                        aes.Mode = CipherMode.ECB;
                        aes.KeySize = 128;
                    }
                    public void Tls() { ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12; }
                }
                """);
        TestSupport.write(project, "cs/Allman.cs", """
                public class Allman
                {
                    public void Hash()
                    {
                        var md5 = MD5.Create();
                    }
                }
                """);
        TestSupport.write(project, "c/crypto.c", """
                #include <openssl/evp.h>
                void enc(void) {
                    EVP_EncryptInit_ex(ctx, EVP_des_ede3_cbc(), NULL, key, iv);
                    HMAC(EVP_sha1(), key, 16, data, len, out, &outlen);
                }
                """);
        TestSupport.write(project, "php/crypto.php", """
                <?php
                function hashPassword($p) { return md5($p); }
                function enc($d, $k) { return openssl_encrypt($d, 'aes-128-ecb', $k); }
                """);
        TestSupport.write(project, "ruby/crypto.rb", """
                require 'openssl'
                def enc
                  cipher = OpenSSL::Cipher.new('des-cbc')
                  Digest::SHA256.hexdigest('x')
                end
                """);
        TestSupport.write(project, "rust/main.rs", """
                use sha2::{Sha256, Digest};
                fn hash() { let mut h = Sha256::new(); }
                fn enc() { let cipher = Aes256Gcm::new(&key); }
                """);
        TestSupport.write(project, "swift/Crypto.swift", """
                import CryptoKit
                func legacy(data: Data) { let d = Insecure.MD5.hash(data: data) }
                func seal() { let box = try AES.GCM.seal(data, using: key) }
                """);
        TestSupport.write(project, "conf/nginx.conf", """
                server {
                  ssl_protocols TLSv1 TLSv1.2;
                }
                """);

        var scan = new FileSystemProjectScanner(MAX_FILE_BYTES).scan(project);
        List<RulePack> packs = new RulePackLoader(TestSupport.MAPPER).loadBuiltIn();
        result = new RuleBasedCryptoDetector(packs, TestSupport.ASSETS)
                .detect(new DetectionContext(project, scan, SbomResult.empty()));
    }

    private static Set<String> namesIn(String file) {
        return result.assets().stream()
                .filter(a -> a.occurrences().stream().anyMatch(o -> o.file().equals(file)))
                .map(CryptoAsset::name)
                .collect(Collectors.toSet());
    }

    private static Occurrence occurrenceOf(String name, String file) {
        return result.assets().stream()
                .filter(a -> a.name().equals(name))
                .flatMap(a -> a.occurrences().stream())
                .filter(o -> o.file().equals(file))
                .findFirst()
                .orElseThrow(() -> new AssertionError(name + " absent de " + file + " : " + namesIn(file)));
    }

    @Test
    void java() {
        assertThat(namesIn("java/Crypto.java"))
                .contains("AES-GCM-NoPadding", "RSA-1024", "MD5", "Cipher (algorithme non résolu)")
                .doesNotContain("DES");
        Occurrence aes = occurrenceOf("AES-GCM-NoPadding", "java/Crypto.java");
        assertThat(aes.line()).isEqualTo(7);
        assertThat(aes.function()).isEqualTo("Crypto.encrypt");
        assertThat(aes.functions()).contains(CryptoFunction.ENCRYPT, CryptoFunction.DECRYPT);
        assertThat(occurrenceOf("RSA-1024", "java/Crypto.java").functions()).contains(CryptoFunction.KEYGEN);
    }

    @Test
    void kotlin() {
        assertThat(namesIn("kotlin/Hash.kt")).contains("SHA-512");
    }

    @Test
    void python() {
        assertThat(namesIn("python/crypto.py"))
                .contains("SHA-1", "HMAC-SHA-256", "AES-CBC", "RSA-4096", "EC-P-384");
        assertThat(occurrenceOf("SHA-1", "python/crypto.py").function()).isEqualTo("crypto.digest");
    }

    @Test
    void javascript() {
        assertThat(namesIn("js/crypto.js")).contains("MD5", "AES-256-CBC", "RSA-2048", "HMAC-SHA-256");
    }

    @Test
    void go() {
        assertThat(namesIn("go/main.go")).contains("AES-GCM", "MD5", "RSA-2048", "TLS 1.0");
    }

    @Test
    void csharp() {
        assertThat(namesIn("cs/Crypto.cs")).contains("SHA-1", "AES-128-ECB", "TLS 1.2");
        assertThat(occurrenceOf("MD5", "cs/Allman.cs").function()).isEqualTo("Allman.Hash");
    }

    @Test
    void moduleLevelCodeHasNoEnclosingFunction() {
        assertThat(occurrenceOf("TLS 1.0", "go/main.go").function()).isNull();
        assertThat(occurrenceOf("AES-GCM", "go/main.go").function()).isEqualTo("main.Encrypt");
        assertThat(occurrenceOf("HMAC-SHA-256", "js/crypto.js").function()).isNull();
        assertThat(occurrenceOf("AES-256-CBC", "js/crypto.js").function()).isEqualTo("crypto.encrypt");
    }

    @Test
    void c() {
        assertThat(namesIn("c/crypto.c")).contains("3DES-CBC", "HMAC-SHA-1").doesNotContain("SHA-1");
    }

    @Test
    void php() {
        assertThat(namesIn("php/crypto.php")).contains("MD5", "AES-128-ECB");
    }

    @Test
    void ruby() {
        assertThat(namesIn("ruby/crypto.rb")).contains("DES-CBC", "SHA-256");
    }

    @Test
    void rust() {
        assertThat(namesIn("rust/main.rs")).contains("SHA-256", "AES-256-GCM");
    }

    @Test
    void swift() {
        assertThat(namesIn("swift/Crypto.swift")).contains("MD5", "AES-GCM");
    }

    @Test
    void configuration() {
        assertThat(namesIn("conf/nginx.conf")).contains("TLS 1.0", "TLS 1.2");
    }

    @Test
    void keyFileFlowsAreReported() {
        assertThat(result.fileFlows())
                .extracting(FileFlow::materialFile, FileFlow::produces)
                .contains(org.assertj.core.groups.Tuple.tuple("private.pem", true),
                        org.assertj.core.groups.Tuple.tuple("server.key", true));
    }

    @Test
    void unresolvedCallsProduceAWarning() {
        assertThat(result.warnings()).anyMatch(w -> w.contains("non résolu"));
    }

    @Test
    void allBuiltInRulePacksLoad() {
        List<RulePack> packs = new RulePackLoader(TestSupport.MAPPER).loadBuiltIn();
        assertThat(packs).extracting(RulePack::id)
                .contains("java", "python", "javascript", "go", "csharp", "c", "php", "ruby", "rust", "swift", "config", "jwt");
    }
}
