package com.chiffrium.domain.policy;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.stream.Stream;

/**
 * Catalogue des algorithmes et paramètres connus, avec leur politique. Source de vérité unique
 * pour la détection (alias) et l'évaluation (statuts) : ajouter un algorithme ne demande aucun code.
 *
 * @param schemaVersion version du format du catalogue
 * @param algorithms    algorithmes et protocoles
 * @param modes         modes d'opération
 * @param paddings      schémas de bourrage
 * @param curves        courbes elliptiques
 * @param policy        politique d'entreprise dont ce catalogue est issu (null : catalogue local)
 */
public record AlgorithmCatalog(
        int schemaVersion,
        List<AlgorithmDefinition> algorithms,
        List<ParameterDefinition> modes,
        List<ParameterDefinition> paddings,
        List<ParameterDefinition> curves,
        Policy policy) {

    /** 8 octets (16 caractères) : assez pour comparer deux installations d'un coup d'œil. */
    private static final int FINGERPRINT_BYTES = 8;
    private static final Pattern ID_PATTERN = Pattern.compile("[a-z0-9][a-z0-9.\\-]*");
    private static final Pattern ALIAS_PATTERN = Pattern.compile("[a-z0-9]+");
    private static final Pattern OID_PATTERN = Pattern.compile("[0-2](\\.\\d+)+");

    public AlgorithmCatalog {
        algorithms = algorithms == null ? List.of() : List.copyOf(algorithms);
        modes = modes == null ? List.of() : List.copyOf(modes);
        paddings = paddings == null ? List.of() : List.copyOf(paddings);
        curves = curves == null ? List.of() : List.copyOf(curves);
    }

    /** Catalogue sans politique publiée : l'usage courant d'un poste isolé. */
    public AlgorithmCatalog(int schemaVersion, List<AlgorithmDefinition> algorithms, List<ParameterDefinition> modes,
                            List<ParameterDefinition> paddings, List<ParameterDefinition> curves) {
        this(schemaVersion, algorithms, modes, paddings, curves, null);
    }

    /** Le même catalogue, avec une autre politique attachée. */
    public AlgorithmCatalog withPolicy(Policy newPolicy) {
        return new AlgorithmCatalog(schemaVersion, algorithms, modes, paddings, curves, newPolicy);
    }

    /**
     * Politique publiée par une organisation, pour qu'une installation sache ce qu'elle applique et d'où cela
     * vient. L'empreinte est calculée sur le contenu : deux serveurs qui affichent la même version et la même
     * empreinte appliquent exactement les mêmes règles.
     *
     * @param name        nom de la politique ("Politique Groupe 2026")
     * @param version     numéro, incrémenté à chaque publication
     * @param publishedBy compte qui a publié
     * @param publishedAt date de publication
     * @param fingerprint empreinte SHA-256 du contenu, tronquée, en hexadécimal
     */
    public record Policy(String name, int version, String publishedBy, java.time.Instant publishedAt,
                         String fingerprint) {
    }

    /** Empreinte du contenu (hors politique) : ce qui distingue deux catalogues, pas leur étiquette. */
    public String fingerprint() {
        StringBuilder canonical = new StringBuilder().append(schemaVersion).append('\n');
        algorithms.stream().map(AlgorithmDefinition::toString).sorted().forEach(a -> canonical.append(a).append('\n'));
        for (List<ParameterDefinition> parameters : List.of(modes, paddings, curves)) {
            parameters.stream().map(ParameterDefinition::toString).sorted()
                    .forEach(p -> canonical.append(p).append('\n'));
        }
        try {
            byte[] digest = java.security.MessageDigest.getInstance("SHA-256")
                    .digest(canonical.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8));
            StringBuilder hex = new StringBuilder();
            for (int i = 0; i < FINGERPRINT_BYTES; i++) {
                hex.append(String.format("%02x", digest[i]));
            }
            return hex.toString();
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 indisponible", e);
        }
    }

    public Optional<AlgorithmDefinition> findAlgorithm(String id) {
        return algorithms.stream().filter(a -> a.id().equals(id)).findFirst();
    }

    public Optional<AlgorithmDefinition> findByOid(String oid) {
        if (oid == null || oid.isBlank()) {
            return Optional.empty();
        }
        return algorithms.stream()
                .filter(a -> a.oids().stream().anyMatch(ref -> ref.oid().equals(oid.trim())))
                .findFirst();
    }

    public Optional<ParameterDefinition> findMode(String name) {
        return findParameter(modes, name);
    }

    public Optional<ParameterDefinition> findPadding(String name) {
        return findParameter(paddings, name);
    }

    public Optional<ParameterDefinition> findCurve(String name) {
        return findParameter(curves, name);
    }

    private static Optional<ParameterDefinition> findParameter(List<ParameterDefinition> list, String name) {
        if (name == null) {
            return Optional.empty();
        }
        return list.stream().filter(p -> p.name().equalsIgnoreCase(name) || p.id().equalsIgnoreCase(name)).findFirst();
    }

    /**
     * Retourne une copie du catalogue où l'entrée de même identifiant est remplacée (ou ajoutée).
     */
    public AlgorithmCatalog withAlgorithm(AlgorithmDefinition definition) {
        List<AlgorithmDefinition> updated = new ArrayList<>(algorithms);
        updated.removeIf(a -> a.id().equals(definition.id()));
        updated.add(definition);
        return new AlgorithmCatalog(schemaVersion, updated, modes, paddings, curves);
    }

    /**
     * Vérifie la cohérence du catalogue (identifiants uniques, alias bien formés, OID valides).
     *
     * @return la liste des erreurs, vide si le catalogue est valide
     */
    public List<String> validate() {
        List<String> errors = new ArrayList<>();
        if (algorithms.isEmpty()) {
            // Un import vide (fichier tronqué, mauvais fichier) effacerait toute la politique.
            errors.add("catalogue vide : au moins un algorithme est requis");
        }
        Set<String> ids = new HashSet<>();
        for (AlgorithmDefinition def : algorithms) {
            String where = "algorithme '" + def.id() + "'";
            if (def.id() == null || !ID_PATTERN.matcher(def.id()).matches()) {
                errors.add(where + " : identifiant invalide (minuscules, chiffres, '.', '-')");
            }
            if (!ids.add(def.id())) {
                errors.add(where + " : identifiant dupliqué");
            }
            if (def.name() == null || def.name().isBlank()) {
                errors.add(where + " : nom obligatoire");
            }
            if (def.aliases().isEmpty() && def.tokens().isEmpty()) {
                errors.add(where + " : au moins un alias ou token est requis pour la détection");
            }
            validateAliases(where, def.aliases(), def.tokens(), errors);
            validateOids(where, def.oids(), errors);
            for (AlgorithmDefinition.OidRef ref : def.oids()) {
                requireKnown(where, ref, "mode", ref.mode(), modes.stream().map(ParameterDefinition::id), errors);
                requireKnown(where, ref, "bourrage", ref.padding(), paddings.stream().map(ParameterDefinition::id),
                        errors);
                requireKnown(where, ref, "algorithme associé", ref.component(),
                        algorithms.stream().map(AlgorithmDefinition::id), errors);
            }
        }
        for (List<ParameterDefinition> group : List.of(modes, paddings, curves)) {
            for (ParameterDefinition param : group) {
                String where = "paramètre '" + param.id() + "'";
                validateAliases(where, param.aliases(), param.tokens(), errors);
                validateOids(where, param.oids(), errors);
            }
        }
        return errors;
    }

    private static void validateOids(String where, List<AlgorithmDefinition.OidRef> oids, List<String> errors) {
        oids.stream()
                .filter(ref -> ref.oid() == null || !OID_PATTERN.matcher(ref.oid()).matches())
                .forEach(ref -> errors.add(where + " : OID invalide '" + ref.oid() + "'"));
    }

    /** Une condition d'OID qui nomme un mode ou un algorithme absent ne serait jamais remplie. */
    private static void requireKnown(String where, AlgorithmDefinition.OidRef ref, String kind, String id,
                                     Stream<String> known, List<String> errors) {
        if (id != null && known.noneMatch(id::equals)) {
            errors.add(where + " : OID " + ref.oid() + " réservé à un " + kind + " inconnu '" + id + "'");
        }
    }

    private static void validateAliases(String where, List<String> aliases, List<String> tokens, List<String> errors) {
        for (String alias : aliases) {
            if (!ALIAS_PATTERN.matcher(alias).matches()) {
                errors.add(where + " : alias '" + alias + "' doit être en minuscules sans séparateur");
            }
        }
        for (String token : tokens) {
            if (!ALIAS_PATTERN.matcher(token).matches()) {
                errors.add(where + " : token '" + token + "' doit être en minuscules sans séparateur");
            }
        }
    }
}
