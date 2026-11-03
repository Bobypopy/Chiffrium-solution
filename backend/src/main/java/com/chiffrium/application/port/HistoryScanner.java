package com.chiffrium.application.port;

import com.chiffrium.domain.model.SecurityFinding;

import java.nio.file.Path;
import java.util.List;
import java.util.Objects;

/**
 * Parcourt l'historique Git à la recherche de secrets et de clés qui ne figurent plus dans l'état actuel du code
 * (supprimés ou modifiés depuis) : ils restent lisibles par quiconque clone le dépôt.
 */
public interface HistoryScanner {

    /**
     * @param root racine analysée : un dépôt Git ou un dossier à l'intérieur d'un dépôt
     * @return constats de l'historique (champ {@code commit} renseigné) et avertissements
     */
    HistoryResult scan(Path root);

    /** Même règle, même fichier, même valeur caviardée : le même secret, quel que soit le commit. */
    static String sameSecret(SecurityFinding finding) {
        return finding.ruleId() + "|" + finding.file() + "|" + Objects.toString(finding.evidence(), "");
    }

    record HistoryResult(List<SecurityFinding> findings, List<String> warnings) {

        public HistoryResult {
            findings = List.copyOf(findings);
            warnings = List.copyOf(warnings);
        }

        public static HistoryResult empty() {
            return new HistoryResult(List.of(), List.of());
        }
    }
}
