package com.chiffrium.domain.model;

import java.util.Comparator;

/**
 * Constat de sécurité localisé (secret exposé, validation TLS désactivée, aléa faible...).
 * Les valeurs sensibles ne sont jamais recopiées : {@code snippet} et {@code evidence} sont caviardés.
 *
 * @param id             identifiant stable (règle + emplacement), utilisé pour comparer deux analyses
 * @param ruleId         règle ayant produit le constat
 * @param category       famille
 * @param severity       gravité (abaissée d'un niveau dans le code de test)
 * @param title          intitulé court
 * @param description    explication du risque
 * @param recommendation correction conseillée
 * @param cwe            référence CWE (ex. CWE-798)
 * @param file           chemin relatif
 * @param line           ligne (1-based)
 * @param column         colonne (1-based)
 * @param snippet        ligne de code caviardée
 * @param evidence       élément déclencheur caviardé (ex. "ghp_...(40)", "TLS_RSA_WITH_RC4_128_SHA")
 * @param language       langage du fichier
 * @param testCode       vrai si le fichier appartient au code de test (souvent de fausses valeurs)
 */
public record SecurityFinding(
        String id,
        String ruleId,
        FindingCategory category,
        Severity severity,
        String title,
        String description,
        String recommendation,
        String cwe,
        String file,
        Integer line,
        Integer column,
        String snippet,
        String evidence,
        Language language,
        boolean testCode) {

    /** Plus grave d'abord, puis par emplacement : ordre stable des rapports. */
    public static final Comparator<SecurityFinding> BY_SEVERITY_THEN_LOCATION = Comparator
            .comparing(SecurityFinding::severity, Comparator.reverseOrder())
            .thenComparing(SecurityFinding::file, Comparator.nullsLast(Comparator.naturalOrder()))
            .thenComparing(SecurityFinding::line, Comparator.nullsLast(Comparator.naturalOrder()))
            .thenComparing(SecurityFinding::ruleId);
}
