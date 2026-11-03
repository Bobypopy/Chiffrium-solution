package com.chiffrium.domain.model;

import java.util.List;

/**
 * Dépendance logicielle issue du SBOM.
 *
 * @param bomRef          bom-ref CycloneDX d'origine
 * @param purl            package URL
 * @param group           groupe / namespace
 * @param scope           portée (required, optional...)
 * @param cryptoLibrary   vrai si la bibliothèque fournit des primitives cryptographiques
 * @param vulnerabilities vulnérabilités connues (OSV)
 * @param licenses        licences déclarées (identifiants SPDX ou expressions)
 * @param licenseRisk     risque juridique déduit des licences
 */
public record Library(
        String bomRef,
        String purl,
        String group,
        String name,
        String version,
        String scope,
        boolean cryptoLibrary,
        List<Vulnerability> vulnerabilities,
        List<String> licenses,
        LicenseRisk licenseRisk) {

    public Library {
        vulnerabilities = vulnerabilities == null ? List.of() : List.copyOf(vulnerabilities);
        licenses = licenses == null ? List.of() : List.copyOf(licenses);
        licenseRisk = licenseRisk == null ? LicenseRisk.UNKNOWN : licenseRisk;
    }

    public Library(String bomRef, String purl, String group, String name, String version, String scope,
                   boolean cryptoLibrary, List<Vulnerability> vulnerabilities) {
        this(bomRef, purl, group, name, version, scope, cryptoLibrary, vulnerabilities, List.of(), LicenseRisk.UNKNOWN);
    }

    public Library withVulnerabilities(List<Vulnerability> found) {
        return new Library(bomRef, purl, group, name, version, scope, cryptoLibrary, found, licenses, licenseRisk);
    }
}
