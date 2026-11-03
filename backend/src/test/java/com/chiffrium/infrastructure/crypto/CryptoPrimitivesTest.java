package com.chiffrium.infrastructure.crypto;

import com.chiffrium.TestSupport;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.Base64;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class CryptoPrimitivesTest {

    private static final byte[] PLAINTEXT = "rapport confidentiel".getBytes(StandardCharsets.UTF_8);
    private static final int FAST_ITERATIONS = 1_000;

    @Test
    void aesGcmRoundTripsWithRandomIvAndDetectsTampering() {
        AesGcmSecretCipher cipher = TestSupport.cipher();
        byte[] first = cipher.encrypt(PLAINTEXT);
        byte[] second = cipher.encrypt(PLAINTEXT);

        assertThat(first).isNotEqualTo(second);
        assertThat(cipher.isEncrypted(first)).isTrue();
        assertThat(cipher.isEncrypted(PLAINTEXT)).isFalse();
        assertThat(cipher.decrypt(first)).isEqualTo(PLAINTEXT);

        first[first.length - 1] ^= 1;
        assertThatThrownBy(() -> cipher.decrypt(first)).isInstanceOf(IllegalStateException.class);
    }

    @Test
    void masterKeyIsGeneratedOnceAndDerivesIndependentKeys(@TempDir Path dir) {
        MasterKey key = MasterKey.load(Optional.empty(), dir.resolve("secrets"));
        MasterKey reloaded = MasterKey.load(Optional.empty(), dir.resolve("secrets"));

        assertThat(dir.resolve("secrets/master.key")).exists();
        assertThat(reloaded.deriveHex("artifacts")).isEqualTo(key.deriveHex("artifacts"));
        assertThat(key.deriveHex("artifacts")).isNotEqualTo(key.deriveHex("settings"));
        assertThat(key.derive("artifacts")).hasSize(MasterKey.KEY_BYTES);
    }

    @Test
    void masterKeyFromEnvironmentTakesPrecedence(@TempDir Path dir) {
        String env = Base64.getEncoder().encodeToString(new byte[MasterKey.KEY_BYTES]);
        MasterKey key = MasterKey.load(Optional.of(env), dir);
        assertThat(dir.resolve("master.key")).doesNotExist();
        assertThat(key.deriveHex("x")).hasSize(MasterKey.KEY_BYTES * 2);
        assertThatThrownBy(() -> MasterKey.load(Optional.of("dHJvcCBjb3VydA=="), dir))
                .isInstanceOf(IllegalStateException.class);
    }

    @Test
    void passwordHashesAreSaltedAndVerifiable() {
        Pbkdf2PasswordHasher hasher = new Pbkdf2PasswordHasher(FAST_ITERATIONS);
        String hash = hasher.hash("phrase de passe".toCharArray());

        assertThat(hash).startsWith("pbkdf2-sha256$" + FAST_ITERATIONS + "$");
        assertThat(hasher.hash("phrase de passe".toCharArray())).isNotEqualTo(hash);
        assertThat(hasher.verify("phrase de passe".toCharArray(), hash)).isTrue();
        assertThat(hasher.verify("autre phrase".toCharArray(), hash)).isFalse();
        assertThat(hasher.verify("phrase de passe".toCharArray(), "corrompu")).isFalse();
    }
}
