package com.chiffrium.domain.model;

/**
 * Informations sur un matériel cryptographique (certificat, clé, keystore) trouvé dans le dépôt.
 *
 * @param materialType   type CycloneDX (private-key, public-key, secret-key, certificate, keystore...)
 * @param format         format de stockage (PEM, DER, PKCS12, JKS...)
 * @param subject        sujet X.509 (certificats uniquement)
 * @param issuer         émetteur X.509 (certificats uniquement)
 * @param notValidBefore début de validité ISO-8601 (certificats uniquement)
 * @param notValidAfter  fin de validité ISO-8601 (certificats uniquement)
 */
public record MaterialInfo(
        String materialType,
        String format,
        String subject,
        String issuer,
        String notValidBefore,
        String notValidAfter) {

    public static MaterialInfo of(String materialType, String format) {
        return new MaterialInfo(materialType, format, null, null, null, null);
    }

    public boolean isPrivate() {
        return "private-key".equals(materialType) || "secret-key".equals(materialType);
    }
}
