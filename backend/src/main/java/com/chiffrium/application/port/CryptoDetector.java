package com.chiffrium.application.port;

import com.chiffrium.domain.model.CryptoAsset;
import com.chiffrium.domain.model.SecurityFinding;

import java.nio.file.Path;
import java.util.List;

/**
 * Moteur de détection d'actifs cryptographiques. Plusieurs implémentations coexistent
 * (cdxgen, règles multi-langages, matériel) ; leurs résultats sont fusionnés.
 */
public interface CryptoDetector {

    /** Nom court, utilisé pour les métriques d'étape. */
    String name();

    DetectionResult detect(DetectionContext context);

    /**
     * @param projectRoot racine du code
     * @param scan        résultat du parcours du projet
     * @param sbom        sorties cdxgen (vide si cdxgen n'a pas été exécuté)
     */
    record DetectionContext(Path projectRoot, ProjectScanner.ScanResult scan, SbomGenerator.SbomResult sbom) {
    }

    /**
     * @param assets    actifs détectés (non fusionnés, non évalués)
     * @param fileFlows lectures/écritures de fichiers de matériel cryptographique
     * @param warnings  problèmes non bloquants
     * @param findings  constats de sécurité (secrets, validation TLS désactivée...)
     * @param callEdges appels entre fonctions du projet trouvés dans le code (complètent ceux de cdxgen)
     */
    record DetectionResult(List<CryptoAsset> assets, List<FileFlow> fileFlows, List<String> warnings,
                           List<SecurityFinding> findings, List<CallEdgeExtractor.CallEdge> callEdges) {

        public DetectionResult {
            assets = List.copyOf(assets);
            fileFlows = List.copyOf(fileFlows);
            warnings = List.copyOf(warnings);
            findings = List.copyOf(findings);
            callEdges = List.copyOf(callEdges);
        }

        public DetectionResult(List<CryptoAsset> assets, List<FileFlow> fileFlows, List<String> warnings,
                               List<SecurityFinding> findings) {
            this(assets, fileFlows, warnings, findings, List.of());
        }

        public DetectionResult(List<CryptoAsset> assets, List<FileFlow> fileFlows, List<String> warnings) {
            this(assets, fileFlows, warnings, List.of());
        }

        public static DetectionResult of(List<CryptoAsset> assets) {
            return new DetectionResult(assets, List.of(), List.of());
        }
    }

    /**
     * Lecture ou écriture d'un fichier de clé/certificat par une fonction.
     *
     * @param materialFile nom du fichier manipulé (ex. "private.pem")
     * @param sourceFile   fichier source contenant l'opération
     * @param line         ligne de l'opération
     * @param function     fonction englobante
     * @param produces     vrai pour une écriture, faux pour une lecture
     */
    record FileFlow(String materialFile, String sourceFile, Integer line, String function, boolean produces) {
    }
}
