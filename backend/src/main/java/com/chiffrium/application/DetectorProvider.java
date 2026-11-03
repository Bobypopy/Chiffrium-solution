package com.chiffrium.application;

import com.chiffrium.application.port.CryptoDetector;
import com.chiffrium.domain.asset.AssetFactory;

import java.util.List;

/**
 * Fournit les détecteurs pour une analyse. Les détecteurs dépendent du catalogue (via la fabrique
 * d'actifs), qui peut être modifié entre deux analyses : ils sont donc créés à chaque exécution.
 */
@FunctionalInterface
public interface DetectorProvider {

    List<CryptoDetector> detectors(AssetFactory assetFactory);
}
