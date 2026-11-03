package com.chiffrium.application.port;

import java.util.Optional;

/**
 * Stockage d'objets pour les artefacts d'analyse (déjà chiffrés par l'appelant) : dossier local ou partagé, ou
 * stockage compatible S3 (MinIO auto-hébergé, Garage, Ceph, AWS S3...) pour plusieurs répliques.
 * Les clés sont de la forme {@code <idAnalyse>/<fichier>}.
 */
public interface ArtifactStore {

    void put(String key, byte[] content);

    Optional<byte[]> get(String key);

    /** Supprime tous les objets dont la clé commence par le préfixe. */
    void deletePrefix(String prefix);

    /** Volume occupé par les objets du préfixe, en octets. */
    long size(String prefix);
}
