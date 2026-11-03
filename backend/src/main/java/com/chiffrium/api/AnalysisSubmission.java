package com.chiffrium.api;

import com.chiffrium.domain.model.AnalysisRequest;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * Corps de POST /api/analyses. Accepte une cible unique ({@code target}) ou une liste ({@code targets}),
 * ce qui remplace l'ancien import d'un fichier .txt/.csv d'URL.
 *
 * @param targets             liste de cibles (une analyse par cible)
 * @param branch              branche Git
 * @param recurseSubmodules   cloner les sous-modules (défaut : oui)
 * @param runCdxgen           lancer cdxgen (défaut : oui)
 * @param scanVulnerabilities rechercher les vulnérabilités OSV (défaut : oui)
 * @param cdxgenTimeoutSeconds délai maximal de cdxgen
 * @param groupId             groupe auquel rattacher les analyses (null : privées)
 */
public record AnalysisSubmission(
        String target,
        List<String> targets,
        String branch,
        Boolean recurseSubmodules,
        Boolean runCdxgen,
        Boolean scanVulnerabilities,
        Integer cdxgenTimeoutSeconds,
        String groupId) {

    static final int MAX_TARGETS = 50;
    static final int MAX_TARGET_LENGTH = 2_048;

    /**
     * @throws IllegalArgumentException si la demande est invalide (message destiné à l'utilisateur)
     */
    List<AnalysisRequest> toRequests() {
        List<String> all = new ArrayList<>();
        if (target != null && !target.isBlank()) {
            all.add(target.trim());
        }
        if (targets != null) {
            targets.stream().filter(Objects::nonNull).map(String::trim).filter(t -> !t.isEmpty()).forEach(all::add);
        }
        List<String> unique = all.stream().distinct().toList();
        if (unique.isEmpty()) {
            throw new IllegalArgumentException("Au moins une cible (URL Git https ou chemin autorisé) est requise.");
        }
        if (unique.size() > MAX_TARGETS) {
            throw new IllegalArgumentException("Au plus " + MAX_TARGETS + " cibles par demande.");
        }
        unique.stream().filter(t -> t.length() > MAX_TARGET_LENGTH).findFirst().ifPresent(t -> {
            throw new IllegalArgumentException("Cible trop longue (" + MAX_TARGET_LENGTH + " caractères max).");
        });
        return unique.stream()
                .map(t -> new AnalysisRequest(t, branch,
                        !Boolean.FALSE.equals(recurseSubmodules),
                        !Boolean.FALSE.equals(runCdxgen),
                        !Boolean.FALSE.equals(scanVulnerabilities),
                        cdxgenTimeoutSeconds))
                .toList();
    }
}
