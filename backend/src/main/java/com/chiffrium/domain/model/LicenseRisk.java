package com.chiffrium.domain.model;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;

import java.util.Arrays;
import java.util.Locale;

/**
 * Risque juridique d'une licence de dépendance pour un logiciel diffusé sous licence propriétaire,
 * du moins au plus contraignant.
 */
public enum LicenseRisk {
    /** MIT, Apache-2.0, BSD... : attribution seulement. */
    PERMISSIVE,
    /** LGPL, MPL, EPL... : obligations limitées aux fichiers ou à la bibliothèque modifiés. */
    WEAK_COPYLEFT,
    /** Licence inconnue ou absente : droits d'usage non établis, à vérifier. */
    UNKNOWN,
    /** GPL, AGPL, SSPL... : l'œuvre dérivée doit être publiée sous la même licence (AGPL : même en SaaS). */
    STRONG_COPYLEFT;

    @JsonValue
    public String id() {
        return name().toLowerCase(Locale.ROOT).replace('_', '-');
    }

    @JsonCreator
    public static LicenseRisk fromId(String value) {
        return Arrays.stream(values()).filter(r -> r.id().equalsIgnoreCase(value) || r.name().equalsIgnoreCase(value))
                .findFirst().orElseThrow(() -> new IllegalArgumentException("Risque de licence inconnu : " + value));
    }
}
