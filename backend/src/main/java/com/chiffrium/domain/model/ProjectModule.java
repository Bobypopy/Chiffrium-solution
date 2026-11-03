package com.chiffrium.domain.model;

import java.util.List;
import java.util.Set;

/**
 * Sous-projet détecté lors du parcours récursif du dépôt (module Maven, package npm, dépôt Git imbriqué...).
 *
 * @param path          chemin relatif à la racine ("." pour la racine)
 * @param languages     langages détectés dans ce module
 * @param manifests     fichiers manifestes trouvés (pom.xml, package.json, go.mod...)
 * @param gitRepository vrai si le dossier est lui-même un dépôt Git (sous-module ou dépôt imbriqué)
 * @param sourceFiles   nombre de fichiers source analysables
 */
public record ProjectModule(
        String path,
        Set<Language> languages,
        List<String> manifests,
        boolean gitRepository,
        int sourceFiles) {

    public ProjectModule {
        languages = languages == null ? Set.of() : Set.copyOf(languages);
        manifests = manifests == null ? List.of() : List.copyOf(manifests);
    }
}
