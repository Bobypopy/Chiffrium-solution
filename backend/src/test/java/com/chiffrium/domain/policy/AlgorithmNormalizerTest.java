package com.chiffrium.domain.policy;

import com.chiffrium.TestSupport;
import com.chiffrium.domain.model.AlgorithmSpec;
import com.chiffrium.domain.model.Primitive;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import static org.assertj.core.api.Assertions.assertThat;

class AlgorithmNormalizerTest {

    private final AlgorithmNormalizer normalizer = TestSupport.NORMALIZER;

    @ParameterizedTest(name = "{0} -> {1}")
    @CsvSource(delimiter = '|', nullValues = "-", value = {
            // brut                                  | nom affiché             | catalogue | primitive
            "AES/CBC/PKCS5Padding                    | AES-CBC-PKCS7           | aes       | block-cipher",
            "AES/GCM/NoPadding                       | AES-GCM-NoPadding       | aes       | block-cipher",
            "aes-256-gcm                             | AES-256-GCM             | aes       | block-cipher",
            "aes_128_ecb                             | AES-128-ECB             | aes       | block-cipher",
            "\"AES\"                                 | AES                     | aes       | block-cipher",
            "AESGCM                                  | AES-GCM                 | aes       | block-cipher",
            "DESede/CBC/PKCS5Padding                 | 3DES-CBC-PKCS7          | 3des      | block-cipher",
            "des_ede3_cbc                            | 3DES-CBC                | 3des      | block-cipher",
            "DES                                     | DES                     | des       | block-cipher",
            "SHA-256                                 | SHA-256                 | sha-256   | hash",
            "sha3_256                                | SHA3-256                | sha3-256  | hash",
            "hashlib.md5                             | MD5                     | md5       | hash",
            "SHA                                     | SHA-1                   | sha-1     | hash",
            "SHA512_256                              | SHA-512/256             | sha-512-256 | hash",
            "HmacSHA256                              | HMAC-SHA-256            | hmac      | mac",
            "PBKDF2WithHmacSHA256                    | PBKDF2-HMAC-SHA-256     | pbkdf2    | kdf",
            "PBEWithMD5AndDES                        | PBES1-MD5-DES           | pbe       | kdf",
            "SHA256withRSA                           | SHA-256withRSA          | rsa       | signature",
            "SHA384withECDSA                         | SHA-384withECDSA        | ecdsa     | signature",
            "RSA/ECB/OAEPWithSHA-256AndMGF1Padding   | RSA-SHA-256-OAEP        | rsa       | pke",
            "RSA                                     | RSA                     | rsa       | pke",
            "EC                                      | EC                      | ec        | other",
            "secp256r1                               | EC-P-256                | ec        | other",
            "Ed25519                                 | Ed25519                 | ed25519   | signature",
            "X25519                                  | X25519                  | x25519    | key-agree",
            "ChaCha20-Poly1305                       | ChaCha20-Poly1305       | chacha20-poly1305 | ae",
            "SHA1PRNG                                | SHA1PRNG                | sha1prng  | drbg",
            "TLSv1.2                                 | TLS 1.2                 | tls12     | other",
            "TLSv1                                   | TLS 1.0                 | tls10     | other",
            "TLS1_3_VERSION                          | TLS 1.3                 | tls13     | other",
            "SSLv3                                   | SSL 3.0                 | sslv3     | other",
            "ML-KEM-768                              | ML-KEM-768              | ml-kem    | kem",
            "ML-DSA-65                               | ML-DSA-65               | ml-dsa    | signature",
            "ml_dsa_87                               | ML-DSA-87               | ml-dsa    | signature",
            "MlDsa44                                 | ML-DSA-44               | ml-dsa    | signature",
            "Dilithium3                              | ML-DSA                  | ml-dsa    | signature",
            "SHA1withDSA                             | SHA-1withDSA            | dsa       | signature",
            "Argon2id                                | Argon2                  | argon2    | kdf",
            "RIJNDAEL_128                            | AES-128                 | aes       | block-cipher",
            "JWT alg=none                            | JWT alg=none            | jwt-none  | signature"
    })
    void normalizesKnownSpellings(String raw, String expectedName, String catalogId, String primitive) {
        AlgorithmSpec spec = normalizer.normalize(raw);
        assertThat(spec.catalogId()).isEqualTo(catalogId);
        assertThat(spec.displayName()).isEqualTo(expectedName);
        assertThat(spec.primitive()).isEqualTo(Primitive.fromCycloneDx(primitive));
    }

    @Test
    void recognizesHybridPostQuantumKeyExchangesBeforeTheirClassicalHalf() {
        assertThat(normalizer.normalize("X25519MLKEM768").catalogId()).isEqualTo("hybrid-mlkem");
        assertThat(normalizer.normalize("mlkem768x25519-sha256").catalogId()).isEqualTo("hybrid-mlkem");
        assertThat(normalizer.normalize("X25519Kyber768Draft00").catalogId()).isEqualTo("hybrid-kyber-draft");
        assertThat(normalizer.normalize("sntrup761x25519-sha512@openssh.com").catalogId()).isEqualTo("sntrup761");
        assertThat(normalizer.normalize("X25519").catalogId()).isEqualTo("x25519");
    }

    @Test
    void javaEcbModeIsIgnoredForRsa() {
        assertThat(normalizer.normalize("RSA/ECB/PKCS1Padding").mode()).isNull();
        assertThat(normalizer.normalize("AES/ECB/PKCS5Padding").mode()).isEqualTo("ECB");
    }

    @Test
    void extractsKeySizeOnlyFromDetachedNumbers() {
        assertThat(normalizer.normalize("RSA-2048").keySize()).isEqualTo(2048);
        assertThat(normalizer.normalize("aes256").keySize()).isEqualTo(256);
        assertThat(normalizer.normalize("SHA-256").keySize()).isNull();
        assertThat(normalizer.normalize("RSA/ECB/OAEPWithSHA-256AndMGF1Padding").keySize()).isNull();
    }

    @Test
    void unknownNamesKeepRawValue() {
        AlgorithmSpec spec = normalizer.normalize("MyHomeMadeCipher");
        assertThat(spec.isRecognized()).isFalse();
        assertThat(spec.displayName()).isEqualTo("MyHomeMadeCipher");
        assertThat(normalizer.normalize(null).isRecognized()).isFalse();
    }

    @Test
    void identifiersAreNotConfusedWithAlgorithms() {
        assertThat(normalizer.normalize("deserialize").isRecognized()).isFalse();
        assertThat(normalizer.normalize("algorithm").isRecognized()).isFalse();
        assertThat(normalizer.normalize("transformation").isRecognized()).isFalse();
    }

    @Test
    void assignsOidForSimpleAlgorithms() {
        assertThat(normalizer.normalize("MD5").oid()).isEqualTo("1.2.840.113549.2.5");
        assertThat(normalizer.normalize("HmacSHA256").oid()).isNull();
    }

    /** Entrées ajoutées au catalogue : reconnues, sans voler les noms déjà couverts par une entrée plus précise. */
    @ParameterizedTest(name = "{0} -> {1}")
    @CsvSource(delimiter = '|', value = {
            "GOST3411-2012-256      | streebog",
            "GOST3411               | gost-34.11-94",
            "GOST28147/ECB          | gost-28147",
            "Kuznyechik             | kuznyechik",
            "Dual_EC_DRBG           | dual-ec-drbg",
            "SIKEp434               | sike",
            "ascon128a              | ascon",
            "NTLMv2                 | ntlmv2",
            "NTLM                   | ntlm",
            "sntrup761x25519-sha512 | sntrup761",
            "ntruhps2048677         | ntru",
            "mt19937                | mersenne-twister",
            "crc32                  | crc",
            "XXH3                   | fast-hash",
            "DTLSv1.2               | dtls12",
            "WPA2-PSK               | wpa2",
            "ssh-dss                | dsa",
            "sha512crypt            | sha-crypt",
            "keccak256              | keccak",
            "XChaCha20-Poly1305     | chacha20-poly1305",
            "RIPEMD160              | ripemd-160",
            "RIPEMD256              | ripemd-128"
    })
    void recognizesExtendedCatalogEntries(String raw, String catalogId) {
        assertThat(normalizer.normalize(raw).catalogId()).isEqualTo(catalogId);
    }
}
