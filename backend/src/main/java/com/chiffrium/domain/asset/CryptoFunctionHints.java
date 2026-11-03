package com.chiffrium.domain.asset;

import com.chiffrium.domain.model.CryptoFunction;

import java.util.EnumSet;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * Déduit l'opération cryptographique d'un nom d'appel ("generateKeyPair", "encrypt", "hexdigest"...).
 * Partagé par le détecteur cdxgen et le moteur de règles (DRY).
 */
public final class CryptoFunctionHints {

    /** Ordre significatif : les motifs les plus spécifiques d'abord ("generatesecret" avant "generate"). */
    private static final Map<String, CryptoFunction> HINTS = new LinkedHashMap<>();
    /** Object.hashCode() n'est pas une opération cryptographique. */
    private static final String NOT_CRYPTO_HASH = "hashcode";

    static {
        HINTS.put("generatesecret", CryptoFunction.KEYDERIVE);
        HINTS.put("derive", CryptoFunction.KEYDERIVE);
        HINTS.put("pbkdf", CryptoFunction.KEYDERIVE);
        HINTS.put("generatekey", CryptoFunction.KEYGEN);
        HINTS.put("keygen", CryptoFunction.KEYGEN);
        HINTS.put("generate_private_key", CryptoFunction.KEYGEN);
        HINTS.put("generatekeypair", CryptoFunction.KEYGEN);
        HINTS.put("decrypt", CryptoFunction.DECRYPT);
        HINTS.put("decipher", CryptoFunction.DECRYPT);
        HINTS.put("unwrap", CryptoFunction.DECRYPT);
        HINTS.put("encrypt", CryptoFunction.ENCRYPT);
        HINTS.put("cipher", CryptoFunction.ENCRYPT);
        HINTS.put("seal", CryptoFunction.ENCRYPT);
        HINTS.put("wrap", CryptoFunction.ENCRYPT);
        HINTS.put("verify", CryptoFunction.VERIFY);
        HINTS.put("sign", CryptoFunction.SIGN);
        HINTS.put("digest", CryptoFunction.DIGEST);
        HINTS.put("hash", CryptoFunction.DIGEST);
        HINTS.put("hmac", CryptoFunction.TAG);
        HINTS.put("mac", CryptoFunction.TAG);
        HINTS.put("encapsulate", CryptoFunction.ENCAPSULATE);
        HINTS.put("decapsulate", CryptoFunction.DECAPSULATE);
    }

    private CryptoFunctionHints() {
    }

    /**
     * @return la première opération reconnue dans le nom, ou un ensemble vide
     */
    public static Set<CryptoFunction> fromCallName(String callName) {
        if (callName == null || callName.isBlank()) {
            return Set.of();
        }
        String lower = callName.toLowerCase(Locale.ROOT);
        if (lower.contains(NOT_CRYPTO_HASH)) {
            return Set.of();
        }
        for (Map.Entry<String, CryptoFunction> hint : HINTS.entrySet()) {
            if (lower.contains(hint.getKey())) {
                return EnumSet.of(hint.getValue());
            }
        }
        return Set.of();
    }
}
