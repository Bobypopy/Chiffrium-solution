package com.chiffrium.domain.asset;

import com.chiffrium.domain.model.AlgorithmSpec;
import com.chiffrium.domain.model.AssetType;
import com.chiffrium.domain.model.CryptoAsset;
import com.chiffrium.domain.model.CryptoFunction;
import com.chiffrium.domain.model.DetectionSource;
import com.chiffrium.domain.model.MaterialInfo;
import com.chiffrium.domain.model.Occurrence;
import com.chiffrium.domain.policy.AlgorithmCatalog;
import com.chiffrium.domain.policy.AlgorithmDefinition;
import com.chiffrium.domain.policy.AlgorithmNormalizer;

import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Crée les actifs avec un bom-ref déterministe. Tous les détecteurs passent par cette fabrique, ce qui
 * garantit que deux moteurs trouvant le même algorithme produisent le même identifiant (et donc sont fusionnés).
 */
public final class AssetFactory {

    private static final String ALGORITHM_PREFIX = "crypto/algorithm/";
    private static final String PROTOCOL_PREFIX = "crypto/protocol/";
    private static final String CERTIFICATE_PREFIX = "crypto/certificate/";
    private static final String MATERIAL_PREFIX = "crypto/related-crypto-material/";
    private static final String UNRESOLVED_PREFIX = "crypto/unresolved/";

    private final AlgorithmNormalizer normalizer;

    public AssetFactory(AlgorithmNormalizer normalizer) {
        this.normalizer = normalizer;
    }

    public AlgorithmNormalizer normalizer() {
        return normalizer;
    }

    /**
     * Crée un actif "algorithme" ou "protocole" (selon le catalogue) à partir d'un nom brut.
     */
    public CryptoAsset fromAlgorithmName(String rawName, Occurrence occurrence, Set<CryptoFunction> functions,
                                         DetectionSource source, String description) {
        return fromSpec(normalizer.normalize(rawName), occurrence, functions, source, description);
    }

    public CryptoAsset fromSpec(AlgorithmSpec spec, Occurrence occurrence, Set<CryptoFunction> functions,
                                DetectionSource source, String description) {
        AssetType type = assetTypeOf(spec);
        String prefix = type == AssetType.PROTOCOL ? PROTOCOL_PREFIX : ALGORITHM_PREFIX;
        String bomRef = prefix + spec.displayName() + (spec.oid() == null ? "" : "@" + spec.oid());
        return new CryptoAsset(bomRef, spec.displayName(), type, spec, null, description, functions, Set.of(source),
                occurrence == null ? List.of() : List.of(occurrence), null);
    }

    /**
     * Crée un actif pour un appel d'API cryptographique dont l'algorithme n'a pas pu être résolu
     * statiquement (ex. {@code Cipher.getInstance(algoVariable)}). Il reste visible pour une revue manuelle.
     */
    public CryptoAsset unresolved(String api, Occurrence occurrence, Set<CryptoFunction> functions) {
        AlgorithmSpec spec = new AlgorithmSpec(api, null, api, List.of(), List.of(), null, null, null, null, null, null);
        return new CryptoAsset(UNRESOLVED_PREFIX + api, api + " (algorithme non résolu)", AssetType.ALGORITHM, spec,
                null, "Algorithme fourni dynamiquement : vérification manuelle nécessaire.", functions,
                Set.of(occurrence.source()), List.of(occurrence), null);
    }

    public CryptoAsset certificate(String file, int indexInFile, AlgorithmSpec signatureAlgorithm, MaterialInfo material,
                                   Occurrence occurrence) {
        String bomRef = CERTIFICATE_PREFIX + file + (indexInFile > 0 ? "#" + indexInFile : "");
        String name = material.subject() != null ? material.subject() : file;
        return new CryptoAsset(bomRef, name, AssetType.CERTIFICATE, signatureAlgorithm, material, null, Set.of(),
                Set.of(DetectionSource.MATERIAL), List.of(occurrence), null);
    }

    public CryptoAsset material(String file, MaterialInfo material, AlgorithmSpec algorithm, Occurrence occurrence) {
        String bomRef = MATERIAL_PREFIX + material.materialType() + "/" + file;
        String name = materialName(material, algorithm, file);
        return new CryptoAsset(bomRef, name, AssetType.RELATED_CRYPTO_MATERIAL, algorithm, material, null, Set.of(),
                Set.of(DetectionSource.MATERIAL), List.of(occurrence), null);
    }

    /** Libellés des types de matériel : "private-key (cle.pem)" ne parlait qu'aux initiés. */
    private static final Map<String, String> MATERIAL_LABELS = Map.of(
            "private-key", "Clé privée", "public-key", "Clé publique", "secret-key", "Clé secrète",
            "certificate", "Certificat", "key-store", "Magasin de clés", "csr", "Demande de certificat");

    /** Ex. "Clé privée RSA-1024 (serveur.pem)" : le type, l'algorithme s'il est connu, puis le fichier. */
    static String materialName(MaterialInfo material, AlgorithmSpec algorithm, String file) {
        String type = MATERIAL_LABELS.getOrDefault(material.materialType(), material.materialType());
        String shortFile = file.contains("/") ? file.substring(file.lastIndexOf('/') + 1) : file;
        String algorithmName = algorithm == null ? null : algorithm.displayName();
        return type + (algorithmName == null || algorithmName.isBlank() ? "" : " " + algorithmName)
                + " (" + shortFile + ")";
    }

    private AssetType assetTypeOf(AlgorithmSpec spec) {
        AlgorithmCatalog catalog = normalizer.catalog();
        if (spec.catalogId() == null) {
            return AssetType.ALGORITHM;
        }
        return catalog.findAlgorithm(spec.catalogId()).map(AlgorithmDefinition::assetType).orElse(AssetType.ALGORITHM);
    }
}
