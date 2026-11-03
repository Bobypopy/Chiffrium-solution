package com.chiffrium.domain.security;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * Politique de mot de passe inspirée de l'ANSSI et du NIST SP 800-63B : longueur plutôt que complexité
 * imposée, refus des mots de passe triviaux ou dérivés de l'identifiant.
 */
public final class PasswordPolicy {

    public static final int MIN_LENGTH = 12;
    public static final int MAX_LENGTH = 128;
    private static final int MIN_DISTINCT_CHARACTERS = 5;
    private static final Set<String> FORBIDDEN = Set.of(
            "motdepasse123", "password1234", "azertyuiop12", "qwertyuiop12", "123456789012", "administrateur",
            "chiffrium", "changezmoi123", "bienvenue1234", "welcome12345");

    private PasswordPolicy() {
    }

    /**
     * @return les manquements, vide si le mot de passe est accepté
     */
    public static List<String> violations(String password, String username) {
        List<String> errors = new ArrayList<>();
        if (password == null || password.length() < MIN_LENGTH) {
            errors.add("Au moins " + MIN_LENGTH + " caractères (une phrase de passe est idéale).");
            return errors;
        }
        if (password.length() > MAX_LENGTH) {
            errors.add("Au plus " + MAX_LENGTH + " caractères.");
        }
        String lower = password.toLowerCase(Locale.ROOT);
        if (FORBIDDEN.contains(lower)) {
            errors.add("Mot de passe trop courant.");
        }
        if (username != null && !username.isBlank() && lower.contains(username.toLowerCase(Locale.ROOT))) {
            errors.add("Ne doit pas contenir l'identifiant.");
        }
        if (password.chars().distinct().count() < MIN_DISTINCT_CHARACTERS) {
            errors.add("Trop peu de caractères différents.");
        }
        return errors;
    }
}
