package com.chiffrium.application.port;

import com.chiffrium.application.port.AnalysisRepository.Artifact;
import com.chiffrium.domain.model.AnalysisReport;

import java.nio.file.Path;

/**
 * Export du rapport dans un format tiers (SARIF pour les outils de revue de code, etc.).
 */
public interface ReportExporter {

    /** Artefact produit (nom de fichier et type de contenu). */
    Artifact artifact();

    void export(AnalysisReport report, Path target);
}
