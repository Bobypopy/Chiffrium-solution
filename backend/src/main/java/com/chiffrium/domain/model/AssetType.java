package com.chiffrium.domain.model;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;

import java.util.Arrays;

/**
 * Type d'actif cryptographique CycloneDX 1.6 (cryptoProperties.assetType).
 */
public enum AssetType {
    ALGORITHM("algorithm"),
    CERTIFICATE("certificate"),
    PROTOCOL("protocol"),
    RELATED_CRYPTO_MATERIAL("related-crypto-material");

    private final String cycloneDxValue;

    AssetType(String cycloneDxValue) {
        this.cycloneDxValue = cycloneDxValue;
    }

    @JsonValue
    public String cycloneDxValue() {
        return cycloneDxValue;
    }

    @JsonCreator
    public static AssetType fromCycloneDx(String value) {
        return Arrays.stream(values())
                .filter(t -> t.cycloneDxValue.equalsIgnoreCase(value) || t.name().equalsIgnoreCase(value))
                .findFirst()
                .orElse(ALGORITHM);
    }
}
