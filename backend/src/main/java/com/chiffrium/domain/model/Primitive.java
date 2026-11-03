package com.chiffrium.domain.model;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;

import java.util.Arrays;

/**
 * Primitive cryptographique, valeurs alignées sur CycloneDX 1.6 (cryptoProperties.algorithmProperties.primitive).
 */
public enum Primitive {
    BLOCK_CIPHER("block-cipher"),
    STREAM_CIPHER("stream-cipher"),
    AUTHENTICATED_ENCRYPTION("ae"),
    HASH("hash"),
    MAC("mac"),
    SIGNATURE("signature"),
    PUBLIC_KEY_ENCRYPTION("pke"),
    KEM("kem"),
    KDF("kdf"),
    KEY_AGREEMENT("key-agree"),
    DRBG("drbg"),
    XOF("xof"),
    COMBINER("combiner"),
    OTHER("other"),
    UNKNOWN("unknown");

    private final String cycloneDxValue;

    Primitive(String cycloneDxValue) {
        this.cycloneDxValue = cycloneDxValue;
    }

    @JsonValue
    public String cycloneDxValue() {
        return cycloneDxValue;
    }

    @JsonCreator
    public static Primitive fromCycloneDx(String value) {
        return Arrays.stream(values())
                .filter(p -> p.cycloneDxValue.equalsIgnoreCase(value) || p.name().equalsIgnoreCase(value))
                .findFirst()
                .orElse(UNKNOWN);
    }
}
