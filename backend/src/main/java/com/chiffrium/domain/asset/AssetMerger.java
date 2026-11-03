package com.chiffrium.domain.asset;

import com.chiffrium.domain.model.AlgorithmSpec;
import com.chiffrium.domain.model.CryptoAsset;
import com.chiffrium.domain.model.Occurrence;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * Fusionne les actifs produits par plusieurs détecteurs puis élimine les redondances :
 * <ol>
 *   <li>même bom-ref = même actif (occurrences, sources et fonctions réunies) ;</li>
 *   <li>à un même emplacement, si deux actifs de la même famille existent (ex. "AES" vu par cdxgen et
 *       "AES-ECB-PKCS7" vu par les règles), seule la description la plus précise garde l'occurrence ;</li>
 *   <li>un actif sans emplacement (composant CBOM cdxgen) est retiré s'il est déjà couvert par un actif
 *       localisé, directement ou comme composant (ex. HMAC et SHA-256 dans PBKDF2-HMAC-SHA-256).</li>
 * </ol>
 */
public final class AssetMerger {

    private AssetMerger() {
    }

    public static List<CryptoAsset> merge(Collection<CryptoAsset> assets) {
        List<CryptoAsset> byRef = mergeByBomRef(assets);
        List<CryptoAsset> located = keepMostSpecificPerLocation(byRef);
        return dropCoveredUnlocatedAssets(located);
    }

    private static List<CryptoAsset> mergeByBomRef(Collection<CryptoAsset> assets) {
        Map<String, CryptoAsset> byRef = new LinkedHashMap<>();
        for (CryptoAsset asset : assets) {
            byRef.merge(asset.bomRef(), asset, CryptoAsset::mergeWith);
        }
        return byRef.values().stream().sorted(Comparator.comparing(CryptoAsset::bomRef)).toList();
    }

    private static List<CryptoAsset> keepMostSpecificPerLocation(List<CryptoAsset> assets) {
        // Pour chaque (emplacement, famille), l'actif le plus précis.
        Map<String, CryptoAsset> best = new HashMap<>();
        for (CryptoAsset asset : assets) {
            String family = familyOf(asset);
            if (family == null) {
                continue;
            }
            for (Occurrence occurrence : asset.occurrences()) {
                best.merge(occurrence.locationKey() + "|" + family, asset,
                        (a, b) -> specificity(b) > specificity(a) ? b : a);
            }
        }
        List<CryptoAsset> result = new ArrayList<>();
        for (CryptoAsset asset : assets) {
            String family = familyOf(asset);
            if (family == null || asset.occurrences().isEmpty()) {
                result.add(asset);
                continue;
            }
            List<Occurrence> kept = asset.occurrences().stream()
                    .filter(o -> best.get(o.locationKey() + "|" + family) == asset)
                    .toList();
            if (!kept.isEmpty()) {
                result.add(kept.size() == asset.occurrences().size() ? asset : withOccurrences(asset, kept));
            }
        }
        return result;
    }

    private static List<CryptoAsset> dropCoveredUnlocatedAssets(List<CryptoAsset> assets) {
        Set<String> covered = new HashSet<>();
        for (CryptoAsset asset : assets) {
            if (!asset.occurrences().isEmpty() && asset.algorithm() != null) {
                covered.add(asset.algorithm().catalogId());
                covered.addAll(asset.algorithm().components());
            }
        }
        covered.remove(null);
        return assets.stream()
                .filter(a -> !a.occurrences().isEmpty() || a.algorithm() == null
                        || !covered.contains(a.algorithm().catalogId()))
                .toList();
    }

    /** Une clé ou un certificat n'est pas une autre écriture de l'algorithme vu au même endroit : pas de famille. */
    private static String familyOf(CryptoAsset asset) {
        return asset.algorithm() == null || asset.material() != null ? null : asset.algorithm().catalogId();
    }

    /** Nombre de paramètres connus : plus il est élevé, plus la description est précise. */
    static int specificity(CryptoAsset asset) {
        AlgorithmSpec spec = asset.algorithm();
        if (spec == null) {
            return 0;
        }
        int score = spec.components().size();
        for (Object parameter : new Object[]{spec.mode(), spec.padding(), spec.keySize(), spec.curve()}) {
            if (Objects.nonNull(parameter)) {
                score++;
            }
        }
        return score;
    }

    private static CryptoAsset withOccurrences(CryptoAsset asset, List<Occurrence> occurrences) {
        return new CryptoAsset(asset.bomRef(), asset.name(), asset.assetType(), asset.algorithm(), asset.material(),
                asset.description(), asset.functions(), asset.sources(), occurrences, asset.verdict());
    }
}
