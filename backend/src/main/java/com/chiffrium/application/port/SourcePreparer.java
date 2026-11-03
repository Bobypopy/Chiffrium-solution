package com.chiffrium.application.port;

import com.chiffrium.application.port.ProjectScanner.ScanResult;

import java.nio.file.Path;
import java.util.List;

/**
 * Préparation d'une copie de travail avant la génération du SBOM (ex. créer un fichier de verrouillage
 * manquant pour que les versions exactes des dépendances soient connues). N'est appliquée qu'aux clones
 * Git : un dossier local de l'utilisateur n'est jamais modifié.
 */
public interface SourcePreparer {

    /** Nom court pour les métriques d'étape. */
    String name();

    /**
     * @return remarques lisibles (fichiers générés, échecs non bloquants)
     */
    List<String> prepare(Path root, ScanResult scan);
}
