package com.chiffrium.application.port;

/**
 * Chiffrement authentifié des données sensibles au repos (clés d'API, rapports, CBOM, journaux).
 */
public interface SecretCipher {

    byte[] encrypt(byte[] plaintext);

    /**
     * @throws IllegalStateException si les données ont été altérées ou la clé est différente
     */
    byte[] decrypt(byte[] ciphertext);

    /** Vrai si les octets portent l'en-tête du format chiffré (compatibilité avec des fichiers en clair). */
    boolean isEncrypted(byte[] data);
}
