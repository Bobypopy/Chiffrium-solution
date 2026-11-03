package com.chiffrium.infrastructure.crypto;

import com.chiffrium.application.port.SecretCipher;

import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * Chiffrement authentifié AES-256-GCM (IV aléatoire de 96 bits par message, étiquette de 128 bits).
 * Format : {@code "CAE1" | IV (12 octets) | chiffré + étiquette}.
 */
public final class AesGcmSecretCipher implements SecretCipher {

    private static final byte[] MAGIC = "CAE1".getBytes(StandardCharsets.US_ASCII);
    private static final int IV_BYTES = 12;
    private static final int TAG_BITS = 128;
    private static final String TRANSFORMATION = "AES/GCM/NoPadding";

    private final SecretKeySpec key;
    private final SecureRandom random = new SecureRandom();

    public AesGcmSecretCipher(byte[] keyBytes) {
        this.key = new SecretKeySpec(keyBytes, "AES");
    }

    @Override
    public byte[] encrypt(byte[] plaintext) {
        try {
            byte[] iv = new byte[IV_BYTES];
            random.nextBytes(iv);
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(TAG_BITS, iv));
            cipher.updateAAD(MAGIC);
            byte[] encrypted = cipher.doFinal(plaintext);
            return ByteBuffer.allocate(MAGIC.length + IV_BYTES + encrypted.length)
                    .put(MAGIC).put(iv).put(encrypted).array();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Chiffrement impossible", e);
        }
    }

    @Override
    public byte[] decrypt(byte[] data) {
        if (!isEncrypted(data)) {
            throw new IllegalStateException("Format chiffré non reconnu.");
        }
        try {
            byte[] iv = Arrays.copyOfRange(data, MAGIC.length, MAGIC.length + IV_BYTES);
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(TAG_BITS, iv));
            cipher.updateAAD(MAGIC);
            return cipher.doFinal(data, MAGIC.length + IV_BYTES, data.length - MAGIC.length - IV_BYTES);
        } catch (AEADBadTagException e) {
            throw new IllegalStateException("Données altérées ou clé maîtresse différente.", e);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Déchiffrement impossible", e);
        }
    }

    @Override
    public boolean isEncrypted(byte[] data) {
        return data != null && data.length > MAGIC.length + IV_BYTES
                && Arrays.equals(data, 0, MAGIC.length, MAGIC, 0, MAGIC.length);
    }
}
