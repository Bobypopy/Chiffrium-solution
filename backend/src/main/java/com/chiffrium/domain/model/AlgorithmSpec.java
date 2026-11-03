package com.chiffrium.domain.model;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;
import java.util.Locale;
import java.util.regex.Pattern;

/**
 * Description normalisée d'un algorithme (ou d'un protocole) après analyse de son nom brut.
 *
 * @param rawName     nom tel qu'il apparaît dans le code ("AES/CBC/PKCS5Padding", "SHA256withRSA")
 * @param catalogId   identifiant de l'entrée principale du catalogue (ex. "rsa"), null si inconnue
 * @param family      nom canonique de l'entrée principale (ex. "RSA")
 * @param components  identifiants catalogue des algorithmes secondaires (ex. ["sha-256"] pour SHA256withRSA)
 * @param componentNames noms canoniques des algorithmes secondaires (ex. ["SHA-256"])
 * @param primitive   primitive cryptographique
 * @param mode        mode d'opération (CBC, GCM...) si pertinent
 * @param padding     schéma de bourrage (PKCS5, OAEP...) si pertinent
 * @param keySize     taille de clé / paramètre en bits si connue
 * @param curve       courbe elliptique si pertinente
 * @param oid         OID si connu
 */
public record AlgorithmSpec(
        String rawName,
        String catalogId,
        String family,
        List<String> components,
        List<String> componentNames,
        Primitive primitive,
        String mode,
        String padding,
        Integer keySize,
        String curve,
        String oid) {

    private static final Pattern PARENTHESIS = Pattern.compile("\\s*\\([^)]*\\)");
    private static final Pattern VARIANTS = Pattern.compile("\\s+/\\s+");
    private static final Pattern NOT_ALPHANUMERIC = Pattern.compile("[^a-z0-9]");

    public AlgorithmSpec {
        components = components == null ? List.of() : List.copyOf(components);
        componentNames = componentNames == null ? List.of() : List.copyOf(componentNames);
        primitive = primitive == null ? Primitive.UNKNOWN : primitive;
    }

    public boolean isRecognized() {
        return catalogId != null;
    }

    public AlgorithmSpec withKeySize(Integer newKeySize) {
        return new AlgorithmSpec(rawName, catalogId, family, components, componentNames, primitive, mode, padding,
                newKeySize, curve, oid);
    }

    public AlgorithmSpec withPrimitive(Primitive newPrimitive) {
        return new AlgorithmSpec(rawName, catalogId, family, components, componentNames, newPrimitive, mode, padding,
                keySize, curve, oid);
    }

    /**
     * Nom d'affichage canonique, ex. "AES-256-GCM", "RSA-2048", "SHA-256withRSA", "HMAC-SHA-256".
     * Sert de base au bom-ref : deux écritures du même algorithme ("AES/GCM/NoPadding" et
     * "aes-256-gcm" sans taille) donnent le même nom dès que leurs paramètres coïncident.
     */
    @JsonProperty("name")
    public String displayName() {
        String family = this.family == null ? rawName : this.family;
        boolean composed = !componentNames.isEmpty() || keySize != null || curve != null || mode != null
                || padding != null;
        String base = composed ? part(family) : family;
        List<String> parts = componentNames.stream().map(this::part).toList();
        StringBuilder name = new StringBuilder();
        if (primitive == Primitive.SIGNATURE && !parts.isEmpty()) {
            name.append(String.join("-", parts)).append("with").append(base);
        } else {
            name.append(base);
            parts.forEach(component -> name.append('-').append(component));
        }
        if (keySize != null) {
            name.append('-').append(keySize);
        }
        if (curve != null) {
            name.append('-').append(part(curve));
        }
        if (mode != null) {
            name.append('-').append(part(mode));
        }
        if (padding != null) {
            name.append('-').append(part(padding));
        }
        return name.toString();
    }

    /**
     * Libellé du catalogue dans un nom composé : sans sa précision entre parenthèses ("GOST R 34.10 (signature)"),
     * et, pour une entrée qui regroupe des variantes ("RIPEMD-128 / RIPEMD-256"), la seule écrite dans le nom brut.
     */
    private String part(String label) {
        String bare = PARENTHESIS.matcher(label).replaceAll("").trim();
        if (bare.isEmpty()) {
            return label;
        }
        String written = compact(rawName == null ? "" : rawName);
        List<String> variants = VARIANTS.splitAsStream(bare).filter(v -> written.contains(compact(v))).toList();
        return variants.size() == 1 ? variants.get(0) : bare;
    }

    private static String compact(String text) {
        return NOT_ALPHANUMERIC.matcher(text.toLowerCase(Locale.ROOT)).replaceAll("");
    }
}
