package com.chiffrium.domain.model;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;

import java.util.Arrays;

/**
 * Famille d'un constat de sécurité (au-delà de l'inventaire des algorithmes).
 */
public enum FindingCategory {
    /** Secret en clair dans le code ou la configuration (mot de passe, jeton, clé d'API, clé privée). */
    SECRET("secret", "Secret exposé"),
    /** Validation de certificat ou de nom d'hôte désactivée (attaque de l'homme du milieu). */
    CERTIFICATE_VALIDATION("certificate-validation", "Validation TLS désactivée"),
    /** Générateur pseudo-aléatoire non cryptographique utilisé pour un secret. */
    WEAK_RANDOM("weak-random", "Aléa prévisible"),
    /** Clé, IV, nonce ou sel constant écrit dans le code. */
    HARDCODED_KEY_MATERIAL("hardcoded-key-material", "Matériel cryptographique en dur"),
    /** Dérivation de clé trop faible (itérations insuffisantes, sel absent). */
    WEAK_KEY_DERIVATION("weak-key-derivation", "Dérivation de clé faible"),
    /** Suite de chiffrement TLS obsolète ou sans confidentialité persistante. */
    WEAK_CIPHER_SUITE("weak-cipher-suite", "Suite TLS faible"),
    /** Configuration de protocole qui réactive des algorithmes ou versions interdits. */
    INSECURE_PROTOCOL_CONFIG("insecure-protocol-config", "Configuration TLS/SSH risquée"),
    /** Jeton JWT accepté sans vérification de signature. */
    INSECURE_JWT("insecure-jwt", "JWT non vérifié");

    private final String id;
    private final String label;

    FindingCategory(String id, String label) {
        this.id = id;
        this.label = label;
    }

    @JsonValue
    public String id() {
        return id;
    }

    public String label() {
        return label;
    }

    @JsonCreator
    public static FindingCategory fromId(String value) {
        return Arrays.stream(values())
                .filter(c -> c.id.equalsIgnoreCase(value) || c.name().equalsIgnoreCase(value))
                .findFirst()
                .orElseThrow(() -> new IllegalArgumentException("Catégorie de constat inconnue : " + value));
    }
}
