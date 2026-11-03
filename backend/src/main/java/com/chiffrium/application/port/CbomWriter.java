package com.chiffrium.application.port;

import com.chiffrium.domain.model.CryptoAsset;
import com.chiffrium.domain.model.Library;
import com.chiffrium.domain.model.SourceInfo;

import java.nio.file.Path;
import java.util.List;

/**
 * Produit le CBOM final au format CycloneDX 1.6 : dépendances du SBOM + actifs cryptographiques évalués.
 */
public interface CbomWriter {

    void write(Path target, SbomGenerator.SbomResult sbom, SourceInfo source, List<CryptoAsset> assets,
               List<Library> libraries);
}
