package com.chiffrium.domain.model;

import java.util.List;

/**
 * Résultat de l'évaluation d'un actif par la politique cryptographique.
 *
 * @param status            statut global (le pire des critères évalués)
 * @param severity          sévérité associée
 * @param quantumVulnerable vrai si l'algorithme est cassable par un ordinateur quantique (Shor)
 * @param reasons           justifications lisibles, une par critère non satisfait
 * @param recommendation    action conseillée
 * @param validUntil        dernière année d'utilisation acceptable si connue
 * @param strength          niveau de sécurité classique et post-quantique, null s'il n'est pas établi
 */
public record PolicyVerdict(
        PolicyStatus status,
        Severity severity,
        boolean quantumVulnerable,
        List<String> reasons,
        String recommendation,
        Integer validUntil,
        SecurityStrength strength) {

    public PolicyVerdict {
        reasons = reasons == null ? List.of() : List.copyOf(reasons);
    }

    /** Verdict sans niveau de sécurité établi (matériel de clé, certificat expiré sans algorithme connu...). */
    public PolicyVerdict(PolicyStatus status, Severity severity, boolean quantumVulnerable, List<String> reasons,
                         String recommendation, Integer validUntil) {
        this(status, severity, quantumVulnerable, reasons, recommendation, validUntil, null);
    }

    public static PolicyVerdict unknown(String reason) {
        return new PolicyVerdict(PolicyStatus.UNKNOWN, Severity.INFO, false, List.of(reason),
                "Vérifier manuellement cet usage et compléter le catalogue d'algorithmes.", null);
    }
}
