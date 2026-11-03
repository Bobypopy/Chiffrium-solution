package com.chiffrium.infrastructure.findings;

import com.chiffrium.domain.model.FindingCategory;
import com.chiffrium.domain.model.Language;
import com.chiffrium.domain.model.Severity;

import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Règle de constat compilée (voir {@code resources/findings/*.json} et docs/rules.md).
 *
 * <p>Une règle s'applique soit au contenu ({@code pattern}), soit au nom de fichier ({@code fileName}).
 * Des vérifications complémentaires, toutes optionnelles, filtrent les correspondances :
 * <ul>
 *   <li>{@code secretGroup} : groupe contenant un secret, caviardé, filtré par entropie et par valeurs factices ;</li>
 *   <li>{@code numberGroup} + {@code below} : constat seulement si le nombre capturé est inférieur au seuil ;</li>
 *   <li>{@code listGroup} + {@code listCheck} : liste analysée (suites TLS, algorithmes obligatoires) ;</li>
 *   <li>{@code exclude} : ligne ignorée si elle correspond aussi à ce motif.</li>
 * </ul>
 *
 * @param category        famille du constat
 * @param severity        gravité de base
 * @param cwe             référence CWE
 * @param languages       langages concernés (vide = tous les fichiers texte)
 * @param pattern         motif sur le contenu, ou null pour une règle sur le nom de fichier
 * @param fileName        motif sur le nom de fichier, ou null
 * @param description     risque
 * @param recommendation  correction
 * @param minEntropy      entropie de Shannon minimale du secret (bits par caractère), 0 = pas de filtre
 * @param numberGroup     groupe numérique comparé à {@code below}
 * @param listGroup       groupe contenant une liste
 * @param listCheck       analyse de la liste
 * @param required        éléments obligatoires pour {@link ListCheck#REQUIRE_ALL}
 * @param exclude         motif d'exclusion sur la ligne
 * @param includeComments analyser aussi les lignes de commentaire (secrets)
 */
record FindingRule(
        String id,
        FindingCategory category,
        Severity severity,
        String cwe,
        Set<Language> languages,
        Pattern pattern,
        Pattern fileName,
        String title,
        String description,
        String recommendation,
        String secretGroup,
        double minEntropy,
        String numberGroup,
        Long below,
        String listGroup,
        ListCheck listCheck,
        List<String> required,
        Pattern exclude,
        boolean includeComments) {

    /** Analyse appliquée au groupe {@code listGroup}. */
    enum ListCheck {
        /** Chaque élément est une suite TLS évaluée par {@link CipherSuitePolicy}. */
        CIPHER_SUITES,
        /** Constat si un élément de {@code required} manque (ex. jdk.tls.disabledAlgorithms). */
        REQUIRE_ALL
    }

    FindingRule {
        languages = languages == null ? Set.of() : Set.copyOf(languages);
        required = required == null ? List.of() : List.copyOf(required);
    }

    boolean appliesTo(Language language) {
        return languages.isEmpty() || languages.contains(language);
    }
}
