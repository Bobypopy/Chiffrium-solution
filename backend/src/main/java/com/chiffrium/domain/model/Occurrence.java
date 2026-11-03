package com.chiffrium.domain.model;

import java.util.Comparator;
import java.util.List;
import java.util.Objects;
import java.util.Set;

/**
 * Emplacement précis où un actif cryptographique apparaît dans le code source.
 *
 * @param file      chemin relatif à la racine du projet analysé (séparateur '/')
 * @param line      numéro de ligne (1-based), null si inconnu
 * @param column    numéro de colonne (1-based), null si inconnu
 * @param function  fonction/méthode englobante si elle a pu être déterminée
 * @param snippet   extrait de code (une ligne, tronqué)
 * @param language  langage du fichier
 * @param source    moteur ayant produit la détection
 * @param ruleId    identifiant de la règle (moteur de règles) ou du tag atom
 * @param functions opérations réalisées à cet endroit (keygen, encrypt, ...)
 * @param trace     trajet de la valeur jusqu'à cet appel quand elle vient d'ailleurs, de l'endroit où elle est
 *                  écrite au dernier relais ("Classe.méthode (chemin:ligne)") ; vide sinon
 */
public record Occurrence(
        String file,
        Integer line,
        Integer column,
        String function,
        String snippet,
        Language language,
        DetectionSource source,
        String ruleId,
        Set<CryptoFunction> functions,
        List<String> trace) {

    /** Ordre stable pour des rapports reproductibles : fichier, ligne, colonne. */
    public static final Comparator<Occurrence> BY_LOCATION = Comparator
            .comparing(Occurrence::file, Comparator.nullsLast(Comparator.naturalOrder()))
            .thenComparing(Occurrence::line, Comparator.nullsLast(Comparator.naturalOrder()))
            .thenComparing(Occurrence::column, Comparator.nullsLast(Comparator.naturalOrder()));

    public Occurrence {
        functions = functions == null ? Set.of() : Set.copyOf(functions);
        trace = trace == null ? List.of() : List.copyOf(trace);
    }

    public Occurrence(String file, Integer line, Integer column, String function, String snippet, Language language,
                      DetectionSource source, String ruleId, Set<CryptoFunction> functions) {
        this(file, line, column, function, snippet, language, source, ruleId, functions, List.of());
    }

    /** Clé d'unicité : deux détections au même endroit (quel que soit le moteur) sont fusionnées. */
    public String locationKey() {
        return file + ':' + Objects.requireNonNullElse(line, 0);
    }
}
