package com.chiffrium.domain.policy;

import com.chiffrium.domain.model.SecurityStrength;

import java.util.Locale;
import java.util.Map;
import java.util.NavigableMap;
import java.util.Optional;
import java.util.Set;
import java.util.TreeMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Niveau de sécurité d'un algorithme selon ses paramètres, pour dire ce qui résiste à un ordinateur quantique.
 *
 * <p>Sources : NIST SP 800-57 partie 1 (équivalences classiques), FIPS 203/204/205 et l'appel à propositions
 * post-quantique du NIST (catégories 1 à 5 : 1 = recherche de clé AES-128, 2 = collision SHA-256, 3 = AES-192,
 * 4 = collision SHA-384, 5 = AES-256). Un algorithme cassé par Shor ne remplit aucune catégorie (0), quelle que
 * soit sa taille. Seuls les algorithmes dont le niveau est établi sont décrits : ailleurs, rien n'est affirmé.
 */
public final class SecurityStrengths {

    /** Chiffrements symétriques dont la sécurité est la taille de clé, connue par le nom ("AES-256"). */
    private static final Set<String> KEYED_CIPHERS = Set.of("aes", "camellia", "aria", "twofish", "serpent",
            "aegis");
    /** Chiffrements à clé de taille unique. */
    private static final Map<String, Integer> FIXED_KEY_CIPHERS = Map.ofEntries(
            Map.entry("chacha20", 256), Map.entry("chacha20-poly1305", 256), Map.entry("salsa20", 256),
            Map.entry("kuznyechik", 256), Map.entry("sm4", 128), Map.entry("seed", 128), Map.entry("ascon", 128),
            Map.entry("des", 56));
    /** Hachages : sécurité en collision (moitié de l'empreinte) et catégorie NIST correspondante. */
    private static final Map<String, SecurityStrength> HASHES = Map.ofEntries(
            Map.entry("sha-224", new SecurityStrength(112, null)),
            Map.entry("sha3-224", new SecurityStrength(112, null)),
            Map.entry("sha-512-224", new SecurityStrength(112, null)),
            Map.entry("sha-256", new SecurityStrength(128, 2)),
            Map.entry("sha3-256", new SecurityStrength(128, 2)),
            Map.entry("sha-512-256", new SecurityStrength(128, 2)),
            Map.entry("sm3", new SecurityStrength(128, 2)),
            Map.entry("sha-384", new SecurityStrength(192, 4)),
            Map.entry("sha3-384", new SecurityStrength(192, 4)),
            Map.entry("sha-512", new SecurityStrength(256, 4)),
            Map.entry("sha3-512", new SecurityStrength(256, 4)));
    /** Schémas post-quantiques : jeu de paramètres -> niveau (FIPS 203, 204, 205, 206 ; HQC ; FrodoKEM). */
    private static final Map<String, Map<Integer, SecurityStrength>> POST_QUANTUM = Map.of(
            "ml-kem", Map.of(512, level(128, 1), 768, level(192, 3), 1024, level(256, 5)),
            "hybrid-mlkem", Map.of(512, level(128, 1), 768, level(192, 3), 1024, level(256, 5)),
            "ml-dsa", Map.of(44, level(128, 2), 65, level(192, 3), 87, level(256, 5)),
            "slh-dsa", Map.of(128, level(128, 1), 192, level(192, 3), 256, level(256, 5)),
            "fn-dsa", Map.of(512, level(128, 1), 1024, level(256, 5)),
            "hqc", Map.of(128, level(128, 1), 192, level(192, 3), 256, level(256, 5)),
            "frodokem", Map.of(640, level(128, 1), 976, level(192, 3), 1344, level(256, 5)));
    /** Logarithme discret et factorisation (RSA, DSA, DH) : taille du module -> bits (SP 800-57, tableau 2). */
    private static final NavigableMap<Integer, Integer> FINITE_FIELD = new TreeMap<>(Map.of(
            1024, 80, 2048, 112, 3072, 128, 7680, 192, 15360, 256));
    private static final Set<String> FINITE_FIELD_IDS = Set.of("rsa", "dsa", "dh", "elgamal", "rsa-x931");
    /** Courbes elliptiques : sécurité en bits (moitié de l'ordre du groupe). */
    private static final Map<String, Integer> CURVES = Map.ofEntries(
            Map.entry("p-192", 96), Map.entry("p-224", 112), Map.entry("secp224k1", 112),
            Map.entry("p-256", 128), Map.entry("secp256k1", 128), Map.entry("frp256v1", 128),
            Map.entry("sm2p256v1", 128), Map.entry("curve25519", 128), Map.entry("p-384", 192),
            Map.entry("p-521", 256), Map.entry("curve448", 224));
    /** Algorithmes sur courbe dont la courbe est fixée par le nom. */
    private static final Map<String, Integer> FIXED_CURVE = Map.ofEntries(
            Map.entry("ed25519", 128), Map.entry("x25519", 128), Map.entry("ed448", 224), Map.entry("x448", 224),
            Map.entry("sm2", 128), Map.entry("jwt-es256", 128), Map.entry("jwt-es256k", 128),
            Map.entry("jwt-es384", 192), Map.entry("jwt-es512", 256));
    private static final Set<String> CURVE_IDS = Set.of("ec", "ecdsa", "ecdh", "ecies", "ecgdsa", "eddsa", "xdh",
            "schnorr");
    private static final String SLH_DSA = "slh-dsa";
    private static final Pattern SLH_DSA_SET = Pattern.compile("(128|192|256)[sf]\\b");
    private static final int AES_128 = 128;
    private static final int AES_192 = 192;
    private static final int AES_256 = 256;

    private SecurityStrengths() {
    }

    /**
     * @param definition        entrée principale du catalogue
     * @param rawName           nom tel qu'écrit dans le code
     * @param keySize           taille de clé ou jeu de paramètres, null si inconnu
     * @param curveId           identifiant catalogue de la courbe, null si absente
     * @param quantumVulnerable vrai si l'usage est cassé par Shor (algorithme principal ou composant)
     * @return le niveau, vide si rien n'est établi
     */
    public static Optional<SecurityStrength> of(AlgorithmDefinition definition, String rawName, Integer keySize,
                                                String curveId, boolean quantumVulnerable) {
        String id = definition.id();
        Integer classical = classicalBits(id, keySize, curveId);
        if (quantumVulnerable) {
            return Optional.of(new SecurityStrength(classical, 0));
        }
        if (POST_QUANTUM.containsKey(id)) {
            Integer parameterSet = keySize == null && SLH_DSA.equals(id) ? slhDsaParameterSet(rawName) : keySize;
            return Optional.ofNullable(parameterSet == null ? null : POST_QUANTUM.get(id).get(parameterSet));
        }
        if (HASHES.containsKey(id)) {
            return Optional.of(HASHES.get(id));
        }
        return classical == null ? Optional.empty() : Optional.of(new SecurityStrength(classical, groverLevel(classical)));
    }

    /** "SLH-DSA-SHA2-192s" : le 2 de SHA2 colle au 192, la taille n'est pas lue comme un nombre isolé. */
    private static Integer slhDsaParameterSet(String rawName) {
        Matcher matcher = SLH_DSA_SET.matcher(rawName == null ? "" : rawName.toLowerCase(Locale.ROOT));
        return matcher.find() ? Integer.valueOf(matcher.group(1)) : null;
    }

    private static Integer classicalBits(String id, Integer keySize, String curveId) {
        if (FIXED_KEY_CIPHERS.containsKey(id)) {
            return FIXED_KEY_CIPHERS.get(id);
        }
        if ("3des".equals(id)) {
            // Triple DES à deux clés (112 bits écrits) : 80 bits ; à trois clés : 112 bits (SP 800-57).
            return keySize != null && keySize <= 112 ? 80 : 112;
        }
        if (KEYED_CIPHERS.contains(id)) {
            return keySize;
        }
        if (FINITE_FIELD_IDS.contains(id)) {
            Map.Entry<Integer, Integer> floor = keySize == null ? null : FINITE_FIELD.floorEntry(keySize);
            return floor == null ? null : floor.getValue();
        }
        if (FIXED_CURVE.containsKey(id)) {
            return FIXED_CURVE.get(id);
        }
        if (CURVE_IDS.contains(id)) {
            if (curveId != null) {
                return CURVES.get(curveId);
            }
            // "EC-256", "secp384" sans courbe reconnue : la taille écrite est celle du groupe.
            return keySize == null ? null : keySize / 2;
        }
        return null;
    }

    /** Recherche de clé accélérée par Grover : catégorie atteinte selon la taille de clé symétrique. */
    private static int groverLevel(int bits) {
        if (bits >= AES_256) {
            return 5;
        }
        if (bits >= AES_192) {
            return 3;
        }
        return bits >= AES_128 ? 1 : 0;
    }

    private static SecurityStrength level(int classicalBits, int nistLevel) {
        return new SecurityStrength(classicalBits, nistLevel);
    }
}
