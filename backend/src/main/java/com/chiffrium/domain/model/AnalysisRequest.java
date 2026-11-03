package com.chiffrium.domain.model;

/**
 * Paramètres d'une analyse.
 *
 * @param target            URL Git (https) ou chemin local autorisé
 * @param branch            branche à analyser (null = branche par défaut)
 * @param recurseSubmodules cloner et analyser les sous-modules Git
 * @param runCdxgen         exécuter cdxgen (SBOM + analyse de flux) ; sinon seul le moteur de règles tourne
 * @param scanVulnerabilities interroger la base OSV pour les dépendances
 * @param cdxgenTimeoutSeconds durée maximale d'une exécution de cdxgen (null = valeur par défaut)
 */
public record AnalysisRequest(
        String target,
        String branch,
        boolean recurseSubmodules,
        boolean runCdxgen,
        boolean scanVulnerabilities,
        Integer cdxgenTimeoutSeconds) {
}
