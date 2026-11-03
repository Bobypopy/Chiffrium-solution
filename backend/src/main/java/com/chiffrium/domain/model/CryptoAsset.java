package com.chiffrium.domain.model;

import java.util.ArrayList;
import java.util.EnumSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * Actif cryptographique (algorithme, protocole, certificat ou matériel de clé) et tous ses emplacements.
 *
 * @param bomRef      identifiant stable, utilisé comme bom-ref CycloneDX
 * @param name        nom d'affichage
 * @param assetType   type CycloneDX
 * @param algorithm   description normalisée de l'algorithme (null pour un matériel sans algorithme connu)
 * @param material    détails du matériel (certificats/clés), null pour un algorithme
 * @param description description libre (ex. fournie par cdxgen)
 * @param functions   union des opérations observées sur toutes les occurrences
 * @param sources     moteurs ayant détecté l'actif
 * @param occurrences emplacements dans le code
 * @param verdict     évaluation de la politique (null avant évaluation)
 */
public record CryptoAsset(
        String bomRef,
        String name,
        AssetType assetType,
        AlgorithmSpec algorithm,
        MaterialInfo material,
        String description,
        Set<CryptoFunction> functions,
        Set<DetectionSource> sources,
        List<Occurrence> occurrences,
        PolicyVerdict verdict) {

    public CryptoAsset {
        Objects.requireNonNull(bomRef, "bomRef");
        functions = functions == null || functions.isEmpty() ? Set.of() : Set.copyOf(functions);
        sources = sources == null || sources.isEmpty() ? Set.of() : Set.copyOf(sources);
        occurrences = occurrences == null ? List.of() : List.copyOf(occurrences);
    }

    public CryptoAsset withVerdict(PolicyVerdict newVerdict) {
        return new CryptoAsset(bomRef, name, assetType, algorithm, material, description, functions, sources,
                occurrences, newVerdict);
    }

    public CryptoAsset withAlgorithm(AlgorithmSpec newAlgorithm) {
        return new CryptoAsset(bomRef, name, assetType, newAlgorithm, material, description, functions, sources,
                occurrences, verdict);
    }

    /**
     * Fusionne deux détections du même actif (même bom-ref) : union des sources, fonctions et
     * occurrences (dédoublonnées par emplacement), en gardant l'information la plus riche.
     */
    public CryptoAsset mergeWith(CryptoAsset other) {
        if (!bomRef.equals(other.bomRef)) {
            throw new IllegalArgumentException("Impossible de fusionner " + bomRef + " et " + other.bomRef);
        }
        Set<CryptoFunction> mergedFunctions = EnumSet.noneOf(CryptoFunction.class);
        mergedFunctions.addAll(functions);
        mergedFunctions.addAll(other.functions);

        Set<DetectionSource> mergedSources = EnumSet.noneOf(DetectionSource.class);
        mergedSources.addAll(sources);
        mergedSources.addAll(other.sources);

        Map<String, Occurrence> byLocation = new LinkedHashMap<>();
        for (Occurrence occurrence : occurrences) {
            byLocation.putIfAbsent(occurrence.locationKey(), occurrence);
        }
        for (Occurrence occurrence : other.occurrences) {
            byLocation.merge(occurrence.locationKey(), occurrence, CryptoAsset::richerOccurrence);
        }
        List<Occurrence> mergedOccurrences = new ArrayList<>(byLocation.values());
        mergedOccurrences.sort(Occurrence.BY_LOCATION);

        return new CryptoAsset(
                bomRef,
                name,
                assetType,
                richerAlgorithm(algorithm, other.algorithm),
                material != null ? material : other.material,
                description != null && !description.isBlank() ? description : other.description,
                mergedFunctions,
                mergedSources,
                mergedOccurrences,
                verdict != null ? verdict : other.verdict);
    }

    private static Occurrence richerOccurrence(Occurrence kept, Occurrence candidate) {
        Set<CryptoFunction> functions = EnumSet.noneOf(CryptoFunction.class);
        functions.addAll(kept.functions());
        functions.addAll(candidate.functions());
        return new Occurrence(
                kept.file(),
                kept.line(),
                kept.column() != null ? kept.column() : candidate.column(),
                kept.function() != null ? kept.function() : candidate.function(),
                kept.snippet() != null ? kept.snippet() : candidate.snippet(),
                kept.language() != null ? kept.language() : candidate.language(),
                kept.source(),
                kept.ruleId(),
                functions);
    }

    private static AlgorithmSpec richerAlgorithm(AlgorithmSpec a, AlgorithmSpec b) {
        if (a == null) {
            return b;
        }
        if (b == null) {
            return a;
        }
        return new AlgorithmSpec(
                a.rawName(),
                a.catalogId() != null ? a.catalogId() : b.catalogId(),
                a.family() != null ? a.family() : b.family(),
                a.components().isEmpty() ? b.components() : a.components(),
                a.componentNames().isEmpty() ? b.componentNames() : a.componentNames(),
                a.primitive() != Primitive.UNKNOWN ? a.primitive() : b.primitive(),
                a.mode() != null ? a.mode() : b.mode(),
                a.padding() != null ? a.padding() : b.padding(),
                a.keySize() != null ? a.keySize() : b.keySize(),
                a.curve() != null ? a.curve() : b.curve(),
                a.oid() != null ? a.oid() : b.oid());
    }
}
