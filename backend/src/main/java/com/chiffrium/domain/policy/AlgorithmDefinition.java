package com.chiffrium.domain.policy;

import com.chiffrium.domain.model.AssetType;
import com.chiffrium.domain.model.PolicyStatus;
import com.chiffrium.domain.model.Primitive;

import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.regex.Pattern;

/**
 * Entrée du catalogue : un algorithme (ou protocole), ses alias de détection et sa politique.
 *
 * @param id                 identifiant stable (minuscules)
 * @param name               nom canonique affiché (ex. "SHA-256")
 * @param primitive          primitive cryptographique
 * @param assetType          algorithm ou protocol
 * @param aliases            formes compactes (minuscules, sans séparateur) reconnues n'importe où dans un nom
 * @param tokens             formes courtes reconnues uniquement comme mot entier (ex. "ec", "dh")
 * @param oids               OID connus, éventuellement réservés à un usage (voir {@link #oidFor})
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

    /**
     * OID qui désigne exactement cet usage : le premier dont toutes les conditions sont remplies, sinon l'OID sans
     * condition s'il est le seul et que l'usage n'associe aucun autre algorithme. Aucun OID plutôt qu'un OID
     * approchant : celui d'AES-128-CBC ne vaut pas pour AES-256-GCM.
     *
     * @param keySize    taille de clé ou jeu de paramètres, null si inconnu
     * @param mode       identifiant catalogue du mode, null si absent
     * @param padding    identifiant catalogue du bourrage, null si absent
     * @param components identifiants catalogue des algorithmes associés (hachage d'une signature...)
     * @param rawName    nom tel qu'écrit dans le code
     */
    public String oidFor(Integer keySize, String mode, String padding, List<String> components, String rawName) {
        String written = OidRef.compact(rawName);
        Optional<OidRef> exact = oids.stream()
                .filter(OidRef::conditional)
                .filter(ref -> ref.matches(keySize, mode, padding, components, written))
                .findFirst();
        if (exact.isPresent()) {
            return exact.get().oid();
        }
        List<OidRef> general = oids.stream().filter(ref -> !ref.conditional()).toList();
        return general.size() == 1 && components.isEmpty() ? general.get(0).oid() : null;
    }

    /**
     * OID d'un usage de l'algorithme. Ses conditions le réservent à cet usage ("aes256-GCM" : AES 256 bits en
     * GCM) ; sans condition, il désigne l'algorithme en général.
     *
     * @param oid         OID
     * @param description libellé de l'OID
     * @param keySize     taille de clé ou jeu de paramètres exigé (256, 768...)
     * @param mode        identifiant du mode exigé (gcm, cbc...)
     * @param padding     identifiant du bourrage exigé (oaep, pss...)
     * @param component   identifiant de l'algorithme associé exigé (sha-256 pour sha256WithRSAEncryption)
     * @param variant     forme compacte qui doit figurer dans le nom écrit ("sha2128s", "448")
     */
    public record OidRef(String oid, String description, Integer keySize, String mode, String padding,
                         String component, String variant) {

        private static final Pattern NOT_ALPHANUMERIC = Pattern.compile("[^a-z0-9]");

        public OidRef(String oid, String description) {
            this(oid, description, null, null, null, null, null);
        }

        /** Vrai si l'OID est réservé à un usage précis. */
        public boolean conditional() {
            return keySize != null || mode != null || padding != null || component != null || variant != null;
        }

        boolean matches(Integer size, String usedMode, String usedPadding, List<String> components, String written) {
            return (keySize == null || keySize.equals(size))
                    && (mode == null || mode.equalsIgnoreCase(usedMode))
                    && (padding == null || padding.equalsIgnoreCase(usedPadding))
                    && (component == null || components.contains(component))
                    && (variant == null || written.contains(variant));
        }

        static String compact(String text) {
            return text == null ? "" : NOT_ALPHANUMERIC.matcher(text.toLowerCase(Locale.ROOT)).replaceAll("");
        }
    }

    /**
     * Règle de taille de clé : si la taille est strictement inférieure à {@code below}, le statut
     * {@code status} s'applique (à partir de {@code fromYear} si renseigné).
     */
    public record KeySizeRule(int below, PolicyStatus status, Integer fromYear, String reason) {
    }
}
