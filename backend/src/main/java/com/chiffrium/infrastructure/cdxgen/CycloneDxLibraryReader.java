package com.chiffrium.infrastructure.cdxgen;

import com.chiffrium.application.port.LibraryReader;
import com.chiffrium.application.port.SbomGenerator.SbomResult;
import com.chiffrium.domain.model.Library;
import com.chiffrium.domain.policy.LicensePolicy;
import com.chiffrium.infrastructure.json.JsonNodes;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * Extrait les dépendances des SBOM (tous écosystèmes confondus, dédoublonnées par purl) et repère
 * celles qui fournissent de la cryptographie. Remplace l'ancien liste_packages.txt (qui ne gardait que
 * le champ "group" et perdait donc tous les paquets npm, PyPI, Go...).
 */
public final class CycloneDxLibraryReader implements LibraryReader {

    private static final Logger LOG = LoggerFactory.getLogger(CycloneDxLibraryReader.class);
    private static final Set<String> LIBRARY_TYPES = Set.of("library", "framework");
    private static final String CRYPTO_TAG = "crypto";

    /**
     * Fragments de purl identifiant des bibliothèques cryptographiques connues, tous écosystèmes.
     * Liste ouverte : compléter ici pour enrichir la détection.
     */
    private static final List<String> CRYPTO_LIBRARY_HINTS = List.of(
            "bouncycastle", "/bcprov", "/bcpkix", "conscrypt", "google.crypto.tink", "/tink", "jasypt",
            "nimbus-jose-jwt", "/jjwt", "spongycastle", "keyczar",
            "pypi/cryptography", "pypi/pycryptodome", "pypi/pycrypto", "pypi/pynacl", "pypi/pyopenssl",
            "pypi/passlib", "pypi/bcrypt", "pypi/argon2-cffi", "pypi/ecdsa", "pypi/rsa@", "pypi/pyjwt",
            "npm/crypto-js", "npm/node-forge", "npm/jsonwebtoken", "npm/jose", "npm/bcrypt", "npm/tweetnacl",
            "npm/libsodium", "npm/%40noble", "npm/@noble", "npm/elliptic", "npm/node-rsa", "npm/sjcl",
            "golang.org/x/crypto", "github.com/golang-jwt", "github.com/cloudflare/circl",
            "nuget/bouncycastle", "nuget/system.security.cryptography", "nuget/libsodium",
            "cargo/ring", "cargo/rustls", "cargo/openssl", "cargo/rsa", "cargo/aes-gcm", "cargo/sha2",
            "cargo/ed25519", "cargo/chacha20poly1305", "cargo/argon2",
            "composer/phpseclib", "composer/defuse", "composer/paragonie",
            "gem/rbnacl", "gem/bcrypt", "gem/jwt", "openssl", "libressl", "boringssl", "wolfssl", "mbedtls",
            "libsodium", "libgcrypt", "nettle", "gnutls");

    private final ObjectMapper mapper;
    private final LicensePolicy licensePolicy;

    public CycloneDxLibraryReader(ObjectMapper mapper, LicensePolicy licensePolicy) {
        this.mapper = mapper;
        this.licensePolicy = licensePolicy;
    }

    @Override
    public List<Library> read(SbomResult sbom) {
        Map<String, Library> byKey = new LinkedHashMap<>();
        for (Path bom : sbom.boms()) {
            try {
                JsonNode root = mapper.readTree(bom.toFile());
                JsonNodes.array(root, "components")
                        .filter(c -> LIBRARY_TYPES.contains(JsonNodes.text(c, "type")))
                        .map(c -> toLibrary(c, licensePolicy))
                        .forEach(lib -> byKey.putIfAbsent(lib.purl() != null ? lib.purl() : lib.bomRef(), lib));
            } catch (IOException e) {
                LOG.warn("SBOM illisible : {}", bom, e);
            }
        }
        return byKey.values().stream()
                .sorted(Comparator.comparing(Library::cryptoLibrary).reversed()
                        .thenComparing(l -> l.name() == null ? "" : l.name()))
                .toList();
    }

    static Library toLibrary(JsonNode component, LicensePolicy licensePolicy) {
        String purl = JsonNodes.text(component, "purl");
        List<String> tags = JsonNodes.texts(component, "tags");
        List<String> licenses = licenses(component);
        return new Library(
                JsonNodes.text(component, "bom-ref"),
                purl,
                JsonNodes.text(component, "group"),
                JsonNodes.text(component, "name"),
                JsonNodes.text(component, "version"),
                JsonNodes.text(component, "scope"),
                tags.contains(CRYPTO_TAG) || isCryptoLibrary(purl),
                List.of(),
                licenses,
                licensePolicy.classify(licenses));
    }

    /**
     * Licences CycloneDX : {@code licenses[].license.id}, {@code licenses[].license.name} ou
     * {@code licenses[].expression}.
     */
    static List<String> licenses(JsonNode component) {
        List<String> result = new ArrayList<>();
        JsonNodes.array(component, "licenses").forEach(entry -> {
            String expression = JsonNodes.text(entry, "expression");
            JsonNode license = entry.path("license");
            String value = expression != null ? expression
                    : JsonNodes.text(license, "id") != null ? JsonNodes.text(license, "id") : JsonNodes.text(license, "name");
            if (value != null && !value.isBlank() && !result.contains(value)) {
                result.add(value.strip());
            }
        });
        return result;
    }

    static boolean isCryptoLibrary(String purl) {
        if (purl == null) {
            return false;
        }
        String lower = purl.toLowerCase(Locale.ROOT);
        return CRYPTO_LIBRARY_HINTS.stream().anyMatch(lower::contains);
    }
}
