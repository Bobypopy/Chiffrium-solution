package com.chiffrium.application.port;

import java.util.List;

/**
 * Extrait les appels entre fonctions à partir des sorties d'analyse de flux (slices cdxgen / atom).
 */
public interface CallEdgeExtractor {

    List<CallEdge> extract(SbomGenerator.SbomResult sbom);

    /**
     * @param caller   fonction appelante (nom qualifié, sans signature)
     * @param callee   fonction appelée (nom qualifié, sans signature)
     * @param file     fichier de l'appelant
     * @param line     ligne de l'appel
     * @param external vrai si l'appelé est une API externe (JDK, bibliothèque)
     */
    record CallEdge(String caller, String callee, String file, Integer line, boolean external) {
    }
}
