package com.chiffrium.domain.model;

import java.util.Map;

/**
 * Indicateurs agrégés d'une analyse, affichés dans le tableau de bord.
 *
 * @param totalAssets       nombre d'actifs cryptographiques
 * @param totalOccurrences  nombre total d'emplacements
 * @param byStatus          répartition par statut de politique (clé : identifiant du statut)
 * @param byPrimitive       répartition par primitive
 * @param byLanguage        nombre d'occurrences par langage
 * @param quantumVulnerable nombre d'actifs vulnérables au quantique
 * @param score             score de sécurité 0-100
 * @param libraries         nombre de dépendances
 * @param cryptoLibraries   nombre de dépendances cryptographiques
 * @param vulnerabilities   nombre de vulnérabilités connues sur les dépendances
 * @param knownExploited    vulnérabilités activement exploitées (catalogue CISA KEV)
 * @param findings          nombre de constats de sécurité
 * @param findingsBySeverity répartition des constats par gravité
 * @param pqc               préparation post-quantique
 * @param byLicenseRisk     dépendances par risque de licence
 */
public record Summary(
        int totalAssets,
        int totalOccurrences,
        Map<String, Integer> byStatus,
        Map<String, Integer> byPrimitive,
        Map<String, Integer> byLanguage,
        int quantumVulnerable,
        int score,
        int libraries,
        int cryptoLibraries,
        int vulnerabilities,
        int knownExploited,
        int findings,
        Map<String, Integer> findingsBySeverity,
        PqcReadiness pqc,
        Map<String, Integer> byLicenseRisk) {

    public Summary {
        byStatus = byStatus == null ? Map.of() : Map.copyOf(byStatus);
        byPrimitive = byPrimitive == null ? Map.of() : Map.copyOf(byPrimitive);
        byLanguage = byLanguage == null ? Map.of() : Map.copyOf(byLanguage);
        findingsBySeverity = findingsBySeverity == null ? Map.of() : Map.copyOf(findingsBySeverity);
        byLicenseRisk = byLicenseRisk == null ? Map.of() : Map.copyOf(byLicenseRisk);
    }
}
