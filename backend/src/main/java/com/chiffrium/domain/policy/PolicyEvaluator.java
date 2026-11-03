package com.chiffrium.domain.policy;

import com.chiffrium.domain.model.AlgorithmSpec;
import com.chiffrium.domain.model.AssetType;
import com.chiffrium.domain.model.CryptoAsset;
import com.chiffrium.domain.model.MaterialInfo;
import com.chiffrium.domain.model.PolicyStatus;
import com.chiffrium.domain.model.PolicyVerdict;
import com.chiffrium.domain.model.Primitive;
import com.chiffrium.domain.model.Severity;

import java.time.Clock;
import java.time.Instant;
import java.time.LocalDate;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.function.Function;

/**
 * Évalue chaque actif par rapport au catalogue. Le verdict est le pire des critères :
 * statut de base, transitions datées (ex. RSA déprécié après 2030), taille de clé,
 * algorithmes secondaires (hachage d'une signature), mode, bourrage et courbe.
 * L'horloge est injectée pour rendre les transitions datées testables.
 */
public final class PolicyEvaluator {

    private static final String PRIVATE_KEY_RECOMMENDATION =
            "Retirer la clé du dépôt, la considérer comme compromise (révocation / rotation) et la stocker dans un "
                    + "coffre-fort de secrets (Vault, KMS, secret Kubernetes).";
    private static final String KEYSTORE_RECOMMENDATION =
            "Vérifier que le keystore ne contient aucune clé privée de production ; sinon le retirer du dépôt.";
    private static final String CERTIFICATE_RENEW_RECOMMENDATION = "Renouveler le certificat.";
    private static final String UNIDENTIFIED_KEY_RECOMMENDATION = "Ouvrir le fichier pour l'identifier ; s'il "
            + "contient une clé privée ou secrète, le retirer du dépôt et considérer la clé comme compromise.";
    private static final String ENCRYPTED_FORMAT_MARKER = "ENCRYPTED";
    private static final Set<Primitive> ASYMMETRIC = EnumSet.of(Primitive.PUBLIC_KEY_ENCRYPTION, Primitive.SIGNATURE,
            Primitive.KEY_AGREEMENT, Primitive.OTHER, Primitive.KEM);

    private final AlgorithmCatalog catalog;
    private final Clock clock;

    public PolicyEvaluator(AlgorithmCatalog catalog, Clock clock) {
        this.catalog = catalog;
        this.clock = clock;
    }

    public CryptoAsset evaluate(CryptoAsset asset) {
        return asset.withVerdict(verdictFor(asset));
    }

    PolicyVerdict verdictFor(CryptoAsset asset) {
        if (asset.assetType() == AssetType.RELATED_CRYPTO_MATERIAL) {
            return evaluateMaterial(asset);
        }
        if (asset.assetType() == AssetType.CERTIFICATE) {
            return evaluateCertificate(asset);
        }
        return evaluateAlgorithm(asset.algorithm());
    }

    PolicyVerdict evaluateAlgorithm(AlgorithmSpec spec) {
        if (spec == null || !spec.isRecognized()) {
            String name = spec == null ? "?" : spec.rawName();
            return PolicyVerdict.unknown("Algorithme \"" + name + "\" absent du catalogue ou non résolu statiquement.");
        }
        Optional<AlgorithmDefinition> found = catalog.findAlgorithm(spec.catalogId());
        if (found.isEmpty()) {
            return PolicyVerdict.unknown("Entrée de catalogue \"" + spec.catalogId() + "\" introuvable.");
        }
        AlgorithmDefinition primary = found.get();
        Accumulator acc = new Accumulator(currentYear());

        acc.applyDefinition(primary, primary.name());
        acc.applyKeySize(primary, spec.keySize());
        for (String componentId : spec.components()) {
            catalog.findAlgorithm(componentId).ifPresent(component ->
                    acc.applyDefinition(component, "composant " + component.name()));
        }
        acc.applyParameter(spec.mode(), catalog::findMode, "mode");
        acc.applyParameter(spec.padding(), catalog::findPadding, "bourrage");
        acc.applyParameter(spec.curve(), catalog::findCurve, "courbe");

        if (acc.recommendation == null && acc.quantumVulnerable) {
            acc.recommendation = primary.recommendation();
        }
        return acc.toVerdict();
    }

    private PolicyVerdict evaluateMaterial(CryptoAsset asset) {
        MaterialInfo material = asset.material();
        if (material != null && material.generated()) {
            // Clé créée à l'exécution : elle n'est pas exposée dans le dépôt, seul son algorithme se juge.
            return evaluateAlgorithm(asset.algorithm());
        }
        if (material != null && material.isPrivate()) {
            boolean encrypted = material.format() != null && material.format().contains(ENCRYPTED_FORMAT_MARKER);
            return new PolicyVerdict(PolicyStatus.DISALLOWED, encrypted ? Severity.HIGH : Severity.CRITICAL, false,
                    List.of(encrypted
                            ? "Clé privée chiffrée versionnée dans le dépôt (exposée à une attaque hors ligne sur le mot de passe)."
                            : "Clé privée ou secrète versionnée dans le dépôt."),
                    PRIVATE_KEY_RECOMMENDATION, null);
        }
        if (material != null && "keystore".equals(material.materialType())) {
            return new PolicyVerdict(PolicyStatus.DEPRECATED, Severity.MEDIUM, false,
                    List.of("Keystore versionné : il peut contenir des clés privées."), KEYSTORE_RECOMMENDATION, null);
        }
        if (asset.algorithm() != null && asset.algorithm().isRecognized()) {
            return evaluateAlgorithm(asset.algorithm());
        }
        if (material != null && !"public-key".equals(material.materialType())) {
            return new PolicyVerdict(PolicyStatus.UNKNOWN, Severity.MEDIUM, false,
                    List.of("Fichier de clé non identifié : son contenu n'a pas pu être lu, il peut contenir une clé "
                            + "privée."), UNIDENTIFIED_KEY_RECOMMENDATION, null);
        }
        return new PolicyVerdict(PolicyStatus.ACCEPTABLE, Severity.INFO, false,
                List.of("Matériel public (clé publique)."), null, null);
    }

    private PolicyVerdict evaluateCertificate(CryptoAsset asset) {
        PolicyVerdict algorithmVerdict = asset.algorithm() != null
                ? evaluateAlgorithm(asset.algorithm())
                : PolicyVerdict.unknown("Algorithme de signature du certificat inconnu.");
        MaterialInfo material = asset.material();
        if (material == null || material.notValidAfter() == null) {
            return algorithmVerdict;
        }
        try {
            Instant expiry = Instant.parse(material.notValidAfter());
            if (expiry.isBefore(clock.instant())) {
                List<String> reasons = new ArrayList<>(algorithmVerdict.reasons());
                reasons.add("Certificat expiré depuis le " + material.notValidAfter().substring(0, "yyyy-MM-dd".length()) + ".");
                return new PolicyVerdict(PolicyStatus.DISALLOWED, Severity.worst(algorithmVerdict.severity(), Severity.HIGH),
                        algorithmVerdict.quantumVulnerable(), reasons, CERTIFICATE_RENEW_RECOMMENDATION,
                        algorithmVerdict.validUntil());
            }
        } catch (DateTimeParseException ignored) {
            // Date non standard : on conserve le verdict de l'algorithme.
        }
        return algorithmVerdict;
    }

    private int currentYear() {
        return LocalDate.now(clock).getYear();
    }

    static Severity severityOf(PolicyStatus status, boolean quantumVulnerable) {
        return switch (status) {
            case DISALLOWED -> Severity.HIGH;
            case DEPRECATED -> Severity.MEDIUM;
            case UNKNOWN -> Severity.INFO;
            case ACCEPTABLE -> quantumVulnerable ? Severity.LOW : Severity.NONE;
            case RECOMMENDED -> Severity.NONE;
        };
    }

    /**
     * Accumule les critères d'évaluation d'un algorithme.
     */
    private static final class Accumulator {
        private final int year;
        private PolicyStatus status = PolicyStatus.RECOMMENDED;
        private boolean quantumVulnerable;
        private final List<String> reasons = new ArrayList<>();
        private String recommendation;
        private Integer validUntil;

        Accumulator(int year) {
            this.year = year;
        }

        void applyDefinition(AlgorithmDefinition def, String label) {
            quantumVulnerable |= def.quantumVulnerable();
            degrade(def.status(), label + " : " + (def.note() == null ? "statut " + def.status().id() : def.note()),
                    def.recommendation());
            if (def.disallowedAfter() != null && year > def.disallowedAfter()) {
                degrade(PolicyStatus.DISALLOWED, label + " : interdit après " + def.disallowedAfter() + ".",
                        def.recommendation());
            } else if (def.deprecatedAfter() != null && year > def.deprecatedAfter()) {
                degrade(PolicyStatus.DEPRECATED, label + " : déprécié après " + def.deprecatedAfter() + ".",
                        def.recommendation());
            }
            limitValidity(def.deprecatedAfter() != null ? def.deprecatedAfter() : def.disallowedAfter());
        }

        void applyKeySize(AlgorithmDefinition def, Integer keySize) {
            if (def.keySizeRules().isEmpty()) {
                return;
            }
            if (keySize == null) {
                // Seule la taille des clés asymétriques varie en pratique au point de changer le verdict.
                if (ASYMMETRIC.contains(def.primitive())) {
                    reasons.add(def.name() + " : taille de clé non déterminée statiquement, à vérifier.");
                }
                return;
            }
            for (AlgorithmDefinition.KeySizeRule rule : def.keySizeRules()) {
                if (keySize >= rule.below()) {
                    continue;
                }
                if (rule.fromYear() == null || year >= rule.fromYear()) {
                    degrade(rule.status(), def.name() + " " + keySize + " bits : " + rule.reason(), def.recommendation());
                } else {
                    limitValidity(rule.fromYear() - 1);
                }
            }
        }

        void applyParameter(String name, Function<String, Optional<ParameterDefinition>> lookup, String kind) {
            if (name == null) {
                return;
            }
            lookup.apply(name).ifPresent(param ->
                    degrade(param.status(), kind + " " + param.name() + " : "
                            + (param.note() == null ? "statut " + param.status().id() : param.note()), null));
        }

        private void degrade(PolicyStatus candidate, String reason, String candidateRecommendation) {
            if (candidate.ordinal() > PolicyStatus.ACCEPTABLE.ordinal()) {
                reasons.add(reason);
                if (recommendation == null && candidateRecommendation != null) {
                    recommendation = candidateRecommendation;
                }
            }
            status = PolicyStatus.worst(status, candidate);
        }

        private void limitValidity(Integer lastYear) {
            if (lastYear != null && (validUntil == null || lastYear < validUntil)) {
                validUntil = lastYear;
            }
        }

        PolicyVerdict toVerdict() {
            if (quantumVulnerable) {
                reasons.add("Vulnérable à un ordinateur quantique (algorithme de Shor) : prévoir une migration post-quantique.");
            }
            return new PolicyVerdict(status, severityOf(status, quantumVulnerable), quantumVulnerable, reasons,
                    recommendation, validUntil);
        }
    }
}
