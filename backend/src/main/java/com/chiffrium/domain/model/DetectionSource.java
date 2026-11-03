package com.chiffrium.domain.model;

import com.fasterxml.jackson.annotation.JsonValue;

/**
 * Origine d'une détection : permet de tracer quel moteur a trouvé quoi.
 */
public enum DetectionSource {
    /** CBOM et slices produits par cdxgen / atom (analyse de flux, Java et Python). */
    CDXGEN("cdxgen"),
    /** Moteur de règles multi-langages interne. */
    RULES("rules"),
    /** Analyse de fichiers de matériel cryptographique (certificats, clés, keystores). */
    MATERIAL("material"),
    /** Chaînes et symboles du code compilé (bytecode Java, assemblages .NET, binaires natifs). */
    BINARY("binary");

    private final String id;

    DetectionSource(String id) {
        this.id = id;
    }

    @JsonValue
    public String id() {
        return id;
    }
}
