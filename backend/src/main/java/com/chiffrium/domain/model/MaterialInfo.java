package com.chiffrium.domain.model;

/**
 * Informations sur un matériel cryptographique (certificat, clé, keystore) trouvé dans le dépôt ou créé par le code.
 *
 * @param materialType   type CycloneDX (private-key, public-key, secret-key, certificate, keystore...)
 * @param format         format de stockage (PEM, DER, PKCS12, JKS...)
 * @param subject        sujet X.509 (certificats uniquement)
 * @param issuer         émetteur X.509 (certificats uniquement)
 * @param notValidBefore début de validité ISO-8601 (certificats uniquement)
 * @param notValidAfter  fin de validité ISO-8601 (certificats uniquement)
 * @param generated      clé créée à l'exécution par le code (génération repérée par une règle), pas un fichier du dépôt
 */
public record MaterialInfo(
        String materialType,
        String format,
        String subject,
        String issuer,
        String notValidBefore,
        String notValidAfter,
        boolean generated) {

    public static MaterialInfo of(String materialType, String format) {
        return new MaterialInfo(materialType, format, null, null, null, null, false);
    }

    public static MaterialInfo generatedKey(String materialType) {
        return new MaterialInfo(materialType, null, null, null, null, null, true);
    }

    public boolean isPrivate() {
        return "private-key".equals(materialType) || "secret-key".equals(materialType);
    }
}
