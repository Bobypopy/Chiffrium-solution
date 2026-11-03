package com.chiffrium.application.port;

import com.chiffrium.domain.model.Language;

import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Génère SBOM / CBOM et slices d'analyse de flux (implémenté par cdxgen).
 */
public interface SbomGenerator {

    SbomResult generate(Path projectRoot, Set<Language> languages, Path outputDir, Duration timeout);

    /** Version de l'outil, pour la traçabilité du rapport ; "indisponible" si l'outil est absent. */
    String version();

    /**
     * @param boms             fichiers CycloneDX produits (un par langage)
     * @param usagesSlices     slices "usages" par langage (appels, types)
     * @param reachablesSlices slices "reachables" par langage (flux, tags crypto)
     * @param warnings         problèmes non bloquants (langage ignoré, timeout...)
     */
    record SbomResult(List<Path> boms,
                      Map<Language, Path> usagesSlices,
                      Map<Language, Path> reachablesSlices,
                      List<String> warnings) {

        public SbomResult {
            boms = List.copyOf(boms);
            usagesSlices = Map.copyOf(usagesSlices);
            reachablesSlices = Map.copyOf(reachablesSlices);
            warnings = List.copyOf(warnings);
        }

        public static SbomResult empty() {
            return new SbomResult(List.of(), Map.of(), Map.of(), List.of());
        }
    }
}
