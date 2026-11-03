package com.chiffrium.infrastructure.rules;

import com.chiffrium.domain.model.Language;

import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Ensemble de règles pour une famille de langages.
 *
 * @param id               identifiant (nom du fichier de règles)
 * @param languages        langages auxquels le paquet s'applique
 * @param commentPrefixes  débuts de ligne signalant un commentaire (les correspondances y sont ignorées)
 * @param functionPatterns déclarations de fonctions (groupe {@code name}), pour trouver la fonction englobante
 * @param classPatterns    déclarations de classes/modules (groupe {@code name}), pour qualifier la fonction
 * @param blockStyle       délimitation des blocs : "braces" (défaut) ou "indent" (Python, Ruby)
 * @param rules            règles, de la plus spécifique à la plus générique (une zone déjà reconnue
 *                         par une règle d'algorithme n'est plus proposée aux suivantes)
 */
public record RulePack(
        String id,
        Set<Language> languages,
        List<String> commentPrefixes,
        List<Pattern> functionPatterns,
        List<Pattern> classPatterns,
        String blockStyle,
        List<Rule> rules) {

    public RulePack {
        languages = Set.copyOf(languages);
        commentPrefixes = List.copyOf(commentPrefixes);
        functionPatterns = List.copyOf(functionPatterns);
        classPatterns = List.copyOf(classPatterns);
        rules = List.copyOf(rules);
    }

    public boolean appliesTo(Language language) {
        return languages.contains(language);
    }
}
