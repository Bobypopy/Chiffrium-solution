package com.chiffrium.domain.policy;

import com.chiffrium.domain.model.AssetType;
import com.chiffrium.domain.model.PolicyStatus;
import com.chiffrium.domain.model.Primitive;

import java.util.List;

/**
 * Entrée du catalogue : un algorithme (ou protocole), ses alias de détection et sa politique.
 *
 * @param id                 identifiant stable (minuscules)
 * @param name               nom canonique affiché (ex. "SHA-256")
 * @param primitive          primitive cryptographique
 * @param assetType          algorithm ou protocol
 * @param aliases            formes compactes (minuscules, sans séparateur) reconnues n'importe où dans un nom
 * @param tokens             formes courtes reconnues uniquement comme mot entier (ex. "ec", "dh")
 * @param oids               OID connus
 * @param status             statut de base
 * @param quantumVulnerable  cassable par l'algorithme de Shor
 * @param keySizeRules       contraintes de taille de clé, évaluées dans l'ordre
 * @param deprecatedAfter    dernière année d'usage normal ; déprécié ensuite
 * @param disallowedAfter    dernière année d'usage toléré ; interdit ensuite
 * @param note               commentaire affiché
 * @param recommendation     remplacement conseillé
 * @param references         références normatives (NIST, ANSSI, politique interne...)
 */
public record AlgorithmDefinition(
        String id,
        String name,
        Primitive primitive,
        AssetType assetType,
        List<String> aliases,
        List<String> tokens,
        List<OidRef> oids,
        PolicyStatus status,
        boolean quantumVulnerable,
        List<KeySizeRule> keySizeRules,
        Integer deprecatedAfter,
        Integer disallowedAfter,
        String note,
        String recommendation,
        List<String> references) {

    public AlgorithmDefinition {
        assetType = assetType == null ? AssetType.ALGORITHM : assetType;
        primitive = primitive == null ? Primitive.UNKNOWN : primitive;
        status = status == null ? PolicyStatus.UNKNOWN : status;
        aliases = aliases == null ? List.of() : List.copyOf(aliases);
        tokens = tokens == null ? List.of() : List.copyOf(tokens);
        oids = oids == null ? List.of() : List.copyOf(oids);
        keySizeRules = keySizeRules == null ? List.of() : List.copyOf(keySizeRules);
        references = references == null ? List.of() : List.copyOf(references);
    }

    public String primaryOid() {
        return oids.isEmpty() ? null : oids.get(0).oid();
    }

    /**
     * @param description libellé de l'OID
     */
    public record OidRef(String oid, String description) {
    }

    /**
     * Règle de taille de clé : si la taille est strictement inférieure à {@code below}, le statut
     * {@code status} s'applique (à partir de {@code fromYear} si renseigné).
     */
    public record KeySizeRule(int below, PolicyStatus status, Integer fromYear, String reason) {
    }
}
