package com.chiffrium.application.port;

import com.chiffrium.domain.model.Language;
import com.chiffrium.domain.model.ProjectModule;

import java.nio.file.Path;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Parcourt récursivement un projet pour détecter ses sous-projets, ses langages et indexer ses fichiers.
 * L'index est partagé par tous les détecteurs : le disque n'est parcouru qu'une fois.
 */
public interface ProjectScanner {

    ScanResult scan(Path root);

    /**
     * Fichier retenu pour l'analyse.
     *
     * @param path     chemin relatif à la racine, séparateur '/'
     * @param language langage du fichier source ou de configuration, null pour un fichier de matériel
     * @param material vrai si le fichier ressemble à un certificat / une clé / un keystore
     * @param size     taille en octets
     */
    record ScannedFile(String path, Language language, boolean material, long size) {
    }

    /**
     * @param modules sous-projets détectés (dont les dépôts Git imbriqués / sous-modules)
     * @param files   fichiers retenus (sources, configuration, matériel, données lues pour les clés et secrets)
     * @param skipped nombre de fichiers ignorés car trop volumineux
     */
    record ScanResult(List<ProjectModule> modules, List<ScannedFile> files, int skipped) {

        public ScanResult {
            modules = List.copyOf(modules);
            files = List.copyOf(files);
        }

        /** Nombre de fichiers par langage (hors matériel). */
        public Map<Language, Integer> fileCounts() {
            Map<Language, Integer> counts = new EnumMap<>(Language.class);
            files.stream()
                    .filter(f -> f.language() != null)
                    .forEach(f -> counts.merge(f.language(), 1, Integer::sum));
            return counts;
        }

        public Set<Language> languages() {
            return fileCounts().keySet();
        }
    }
}
