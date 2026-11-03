package com.chiffrium.domain.policy;

import com.chiffrium.domain.model.PolicyStatus;

import java.util.List;

/**
 * Paramètre d'algorithme évalué séparément : mode d'opération, bourrage ou courbe elliptique.
 *
 * @param id      identifiant stable
 * @param name    nom canonique affiché
 * @param aliases formes compactes reconnues n'importe où
 * @param tokens  formes reconnues uniquement comme mot entier
 * @param status  statut de politique
 * @param note    justification
 */
public record ParameterDefinition(
        String id,
        String name,
        List<String> aliases,
        List<String> tokens,
        PolicyStatus status,
        String note) {

    public ParameterDefinition {
        aliases = aliases == null ? List.of() : List.copyOf(aliases);
        tokens = tokens == null ? List.of() : List.copyOf(tokens);
        status = status == null ? PolicyStatus.UNKNOWN : status;
    }
}
