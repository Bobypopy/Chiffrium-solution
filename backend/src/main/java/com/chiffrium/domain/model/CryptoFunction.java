package com.chiffrium.domain.model;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;

import java.util.Arrays;

/**
 * Opération cryptographique réalisée à un emplacement, valeurs alignées sur CycloneDX 1.6 (cryptoFunctions).
 */
public enum CryptoFunction {
    GENERATE("generate"),
    KEYGEN("keygen"),
    ENCRYPT("encrypt"),
    DECRYPT("decrypt"),
    DIGEST("digest"),
    TAG("tag"),
    KEYDERIVE("keyderive"),
    SIGN("sign"),
    VERIFY("verify"),
    ENCAPSULATE("encapsulate"),
    DECAPSULATE("decapsulate"),
    OTHER("other"),
    UNKNOWN("unknown");

    private final String cycloneDxValue;

    CryptoFunction(String cycloneDxValue) {
        this.cycloneDxValue = cycloneDxValue;
    }

    @JsonValue
    public String cycloneDxValue() {
        return cycloneDxValue;
    }

    @JsonCreator
    public static CryptoFunction fromCycloneDx(String value) {
        return Arrays.stream(values())
                .filter(f -> f.cycloneDxValue.equalsIgnoreCase(value) || f.name().equalsIgnoreCase(value))
                .findFirst()
                .orElse(UNKNOWN);
    }
}
