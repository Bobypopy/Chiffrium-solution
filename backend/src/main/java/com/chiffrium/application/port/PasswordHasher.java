package com.chiffrium.application.port;

/**
 * Hachage de mots de passe (lent et salé).
 */
public interface PasswordHasher {

    String hash(char[] password);

    /** Comparaison en temps constant. */
    boolean verify(char[] password, String stored);
}
