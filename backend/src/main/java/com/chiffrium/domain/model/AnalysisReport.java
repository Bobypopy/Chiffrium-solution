package com.chiffrium.domain.model;

import java.time.Instant;
import java.util.List;
import java.util.Map;

/**
 * Rapport complet d'une analyse (fichier report.json). Remplace analysis_report.json,
 * structure.json, file_metrics.json et liste_packages.txt de la version précédente.
 *
 * @param schemaVersion version du format, à incrémenter à chaque changement incompatible
 * @param analysisId    identifiant de l'analyse
 * @param generatedAt   date de génération
 * @param toolVersions  versions des outils utilisés (analyseur, cdxgen)
 * @param source        source analysée
 * @param summary       indicateurs agrégés
 * @param assets        actifs cryptographiques évalués
 * @param libraries     dépendances (SBOM) avec vulnérabilités
 * @param findings      constats de sécurité (secrets, validation TLS, aléa...), du plus grave au moins grave
 * @param callGraph     graphe fonctions / actifs / fichiers
 * @param steps         métriques des étapes du pipeline
 * @param warnings      avertissements non bloquants rencontrés
 */
public record AnalysisReport(
        int schemaVersion,
        String analysisId,
        Instant generatedAt,
        Map<String, String> toolVersions,
        SourceInfo source,
        Summary summary,
        List<CryptoAsset> assets,
        List<Library> libraries,
        List<SecurityFinding> findings,
        CallGraph callGraph,
        List<StepMetric> steps,
        List<String> warnings) {

    public static final int CURRENT_SCHEMA_VERSION = 3;

    public AnalysisReport {
        toolVersions = toolVersions == null ? Map.of() : Map.copyOf(toolVersions);
        assets = assets == null ? List.of() : List.copyOf(assets);
        libraries = libraries == null ? List.of() : List.copyOf(libraries);
        findings = findings == null ? List.of() : List.copyOf(findings);
        steps = steps == null ? List.of() : List.copyOf(steps);
        warnings = warnings == null ? List.of() : List.copyOf(warnings);
    }
}
