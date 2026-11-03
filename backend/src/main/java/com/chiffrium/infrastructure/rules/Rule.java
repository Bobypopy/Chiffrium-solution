package com.chiffrium.infrastructure.rules;

import com.chiffrium.domain.model.CryptoFunction;
import com.chiffrium.domain.model.Primitive;

import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * Règle de détection compilée.
 *
 * <p>Groupes nommés reconnus dans {@code pattern} :
 * <ul>
 *   <li>{@code algo} : argument à résoudre (littéral, constante, concaténation) ;</li>
 *   <li>{@code name} : nom d'algorithme lu directement dans le code (ex. {@code hashlib.sha256}) ;</li>
 *   <li>{@code mode}, {@code padding}, {@code curve} : paramètres ajoutés au nom ;</li>
 *   <li>{@code size} : taille de clé (en octets pour une règle "keybytes") ; {@code bits} : nombre utilisé
 *       seulement par le gabarit ;</li>
 *   <li>{@code list} : liste d'algorithmes séparés par des virgules / espaces / deux-points ;</li>
 *   <li>{@code api} / {@code op} : API ou opération appelée (détermine fonctions et primitive) ;</li>
 *   <li>{@code file} / {@code mode} (règles "file") : fichier manipulé et mode d'ouverture.</li>
 * </ul>
 *
 * @param id                identifiant unique (traçabilité dans le rapport)
 * @param kind              nature de la règle
 * @param pattern           expression régulière compilée
 * @param algorithm         nom d'algorithme fixe quand l'API l'impose (ex. {@code MD5.Create()})
 * @param template          gabarit du nom, ex. "HMAC-{name}", "PBKDF2WithHmac{algo}"
 * @param map               correspondances de noms (clé en minuscules), ex. "hs256" -> "HMAC-SHA256"
 * @param functions         opérations réalisées
 * @param functionsByApi    opérations selon la valeur du groupe {@code api}
 * @param primitive         primitive imposée si le nom ne suffit pas (ex. createSign -> signature)
 * @param primitiveByApi    primitive selon la valeur du groupe {@code api}
 * @param skipUnrecognized  ignorer les noms absents du catalogue (règles génériques bruyantes)
 * @param direction         "read" ou "write" pour les règles de fichiers sans mode explicite
 * @param key               type de la clé créée par l'appel ("private-key" ou "secret-key"), null sinon
 * @param keyByApi          type de clé selon la valeur du groupe {@code api}
 * @param fallback          détection de repli (nom d'algorithme écrit seul, sans appel reconnu) : ignorée si un
 *                          appel du même fichier utilise déjà cet algorithme
 */
public record Rule(
        String id,
        Kind kind,
        Pattern pattern,
        String algorithm,
        String template,
        Map<String, String> map,
        List<CryptoFunction> functions,
        Map<String, List<CryptoFunction>> functionsByApi,
        Primitive primitive,
        Map<String, Primitive> primitiveByApi,
        boolean skipUnrecognized,
        String direction,
        String key,
        Map<String, String> keyByApi,
        boolean fallback) {

    /** Nature d'une règle. */
    public enum Kind {
        /** Crée une détection d'algorithme. */
        ALGORITHM,
        /** Taille de clé rattachée à la détection précédente la plus proche. */
        KEYSIZE,
        /** Mode d'opération rattaché à la détection précédente la plus proche. */
        MODE,
        /** Bourrage rattaché à la détection précédente la plus proche. */
        PADDING,
        /** Courbe rattachée à la détection précédente la plus proche. */
        CURVE,
        /**
         * Clé tirée au hasard dont la taille est donnée en octets : rattachée au chiffrement symétrique le plus
         * proche, avant ou après (la clé est souvent créée avant d'être utilisée).
         */
        KEYBYTES,
        /** Lecture/écriture d'un fichier de clé ou de certificat. */
        FILE
    }

    public Rule {
        map = map == null ? Map.of() : Map.copyOf(map);
        functions = functions == null ? List.of() : List.copyOf(functions);
        functionsByApi = functionsByApi == null ? Map.of() : Map.copyOf(functionsByApi);
        primitiveByApi = primitiveByApi == null ? Map.of() : Map.copyOf(primitiveByApi);
        keyByApi = keyByApi == null ? Map.of() : Map.copyOf(keyByApi);
    }
}
