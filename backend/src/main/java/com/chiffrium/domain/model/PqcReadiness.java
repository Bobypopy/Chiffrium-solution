package com.chiffrium.domain.model;

import com.fasterxml.jackson.annotation.JsonValue;

import java.util.Locale;

/**
 * État de préparation post-quantique du projet.
 *
 * <p>Seule la cryptographie asymétrique (RSA, ECC, DH) est cassée par l'algorithme de Shor : elle doit migrer
 * vers ML-KEM (FIPS 203) pour l'échange de clés et ML-DSA / SLH-DSA (FIPS 204 / 205) pour la signature,
 * idéalement en mode hybride pendant la transition (recommandation ANSSI / BSI). La symétrique n'est affaiblie
 * que par Grover : AES-256 et SHA-384+ conservent une marge confortable (exigence CNSA 2.0).
 *
 * @param stage                  étape de migration
 * @param quantumVulnerable      actifs asymétriques cassables par Shor
 * @param postQuantum            actifs post-quantiques (ML-KEM, ML-DSA, SLH-DSA, LMS/XMSS, hybrides...)
 * @param symmetricBelow256Bits  chiffrements symétriques de moins de 256 bits (acceptables, mais hors CNSA 2.0)
 */
public record PqcReadiness(Stage stage, int quantumVulnerable, int postQuantum, int symmetricBelow256Bits) {

    /** Étape de migration post-quantique. */
    public enum Stage {
        /** Aucune cryptographie asymétrique détectée. */
        NO_ASYMMETRIC,
        /** Uniquement de l'asymétrique vulnérable : migration à planifier. */
        NOT_STARTED,
        /** Coexistence d'algorithmes vulnérables et post-quantiques (ou hybrides). */
        IN_TRANSITION,
        /** Toute l'asymétrique détectée est post-quantique. */
        READY;

        @JsonValue
        public String id() {
            return name().toLowerCase(Locale.ROOT).replace('_', '-');
        }
    }

    public static PqcReadiness of(int quantumVulnerable, int postQuantum, int symmetricBelow256Bits) {
        Stage stage;
        if (quantumVulnerable == 0 && postQuantum == 0) {
            stage = Stage.NO_ASYMMETRIC;
        } else if (postQuantum == 0) {
            stage = Stage.NOT_STARTED;
        } else if (quantumVulnerable > 0) {
            stage = Stage.IN_TRANSITION;
        } else {
            stage = Stage.READY;
        }
        return new PqcReadiness(stage, quantumVulnerable, postQuantum, symmetricBelow256Bits);
    }
}
