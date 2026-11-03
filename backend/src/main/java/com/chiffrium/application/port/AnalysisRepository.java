package com.chiffrium.application.port;

import com.chiffrium.domain.model.AnalysisJob;
import com.chiffrium.domain.model.AnalysisReport;

import java.nio.file.Path;
import java.util.List;
import java.util.Optional;

/**
 * Persistance des analyses et de leurs artefacts. L'implémentation chiffre les données au repos : les
 * artefacts ne sont donc lus qu'à travers {@link #readArtifact}, jamais directement sur disque.
 */
public interface AnalysisRepository {

    void save(AnalysisJob job);

    Optional<AnalysisJob> find(String id);

    /** Toutes les analyses, de la plus récente à la plus ancienne. */
    List<AnalysisJob> findAll();

    void delete(String id);

    void saveReport(AnalysisReport report);

    /** Rapport déchiffré et désérialisé s'il existe. */
    Optional<AnalysisReport> readReport(String id);

    /** Contenu déchiffré d'un artefact s'il existe. */
    Optional<byte[]> readArtifact(String id, Artifact artifact);

    /** Dossier de travail où le pipeline dépose les artefacts pendant l'analyse (créé si besoin). */
    Path artifactsDir(String id);

    /**
     * Fin d'analyse : chiffre les artefacts restés en clair (CBOM, journal) et supprime (ou chiffre) les
     * sorties brutes de cdxgen.
     */
    void seal(String id, boolean keepRawOutputs);

    /** Espace disque occupé par une analyse, en octets. */
    long sizeOf(String id);

    /** Artefacts publiés d'une analyse. */
    enum Artifact {
        REPORT("report.json", "application/json"),
        CBOM("cbom.json", "application/vnd.cyclonedx+json"),
        SARIF("report.sarif", "application/sarif+json"),
        LOG("analysis.log", "text/plain; charset=utf-8");

        private final String fileName;
        private final String contentType;

        Artifact(String fileName, String contentType) {
            this.fileName = fileName;
            this.contentType = contentType;
        }

        public String fileName() {
            return fileName;
        }

        public String contentType() {
            return contentType;
        }
    }
}
