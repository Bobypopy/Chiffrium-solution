package com.chiffrium.infrastructure.material;

import com.chiffrium.application.port.CryptoDetector;
import com.chiffrium.application.port.ProjectScanner.ScannedFile;
import com.chiffrium.domain.asset.AssetFactory;
import com.chiffrium.domain.model.AlgorithmSpec;
import com.chiffrium.domain.model.CryptoAsset;
import com.chiffrium.domain.model.DetectionSource;
import com.chiffrium.domain.model.MaterialInfo;
import com.chiffrium.domain.model.Occurrence;
import com.chiffrium.infrastructure.scan.ArchiveEntries;
import com.chiffrium.infrastructure.scan.FileClassifier;
import com.chiffrium.infrastructure.scan.FileFailures;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Détecte le matériel cryptographique versionné :
 * <ul>
 *   <li>certificats X.509 (PEM ou DER) : sujet, émetteur, validité, algorithme de signature, taille de clé ;</li>
 *   <li>clés privées (PEM, OpenSSH, PGP, PuTTY), y compris embarquées dans du code source ;</li>
 *   <li>clés publiques (PEM, OpenSSH) avec algorithme et taille ;</li>
 *   <li>keystores (PKCS#12, JKS, BKS) signalés sans être ouverts (mot de passe inconnu) ;</li>
 *   <li>PEM encodé en Base64 (Secret Kubernetes, kubeconfig, valeurs Helm) et clés JWK (RFC 7517).</li>
 * </ul>
 */
public final class MaterialDetector implements CryptoDetector {

    private static final Logger LOG = LoggerFactory.getLogger(MaterialDetector.class);
    private static final Pattern PEM_BLOCK = Pattern.compile(
            "-----BEGIN ([A-Z0-9 ]+)-----(?:\\r?\\n|\\\\n)?([A-Za-z0-9+/=\\s\\\\n:,-]*?)-----END \\1-----");
    private static final Pattern PEM_HEADER = Pattern.compile("-----BEGIN ([A-Z0-9 ]+)-----");
    private static final Pattern SSH_PUBLIC_KEY = Pattern.compile(
            "^(ssh-rsa|ssh-dss|ssh-ed25519|ecdsa-sha2-nistp256|ecdsa-sha2-nistp384|ecdsa-sha2-nistp521)\\s+([A-Za-z0-9+/=]+)",
            Pattern.MULTILINE);
    private static final Set<String> KEYSTORE_EXTENSIONS = Set.of("p12", "pfx", "jks", "keystore", "bks");
    private static final Set<String> DER_CERT_EXTENSIONS = Set.of("der", "cer", "crt");
    private static final Map<String, String> SSH_ALGORITHMS = Map.of(
            "ssh-rsa", "RSA", "ssh-dss", "DSA", "ssh-ed25519", "Ed25519",
            "ecdsa-sha2-nistp256", "ECDSA-P256", "ecdsa-sha2-nistp384", "ECDSA-P384", "ecdsa-sha2-nistp521", "ECDSA-P521");
    private static final String PEM_MARKER = "-----BEGIN ";
    /** "-----BEGIN" encodé en Base64. */
    private static final String BASE64_PEM_MARKER = "LS0tLS1CRUdJTi";
    private static final Pattern BASE64_PEM = Pattern.compile(BASE64_PEM_MARKER + "[A-Za-z0-9+/]+={0,2}");
    private static final String JWK_MARKER = "\"kty\"";
    private static final Pattern JWK = Pattern.compile("\\{[^{}]*\"kty\"\\s*:\\s*\"(?<kty>RSA|EC|OKP|oct)\"[^{}]*}");
    private static final Pattern JWK_PRIVATE_PART = Pattern.compile("\"[dk]\"\\s*:\\s*\"");
    private static final Pattern JWK_CURVE = Pattern.compile("\"crv\"\\s*:\\s*\"([\\w-]+)\"");
    private static final Pattern JWK_MODULUS = Pattern.compile("\"n\"\\s*:\\s*\"([A-Za-z0-9_-]+)\"");
    private static final String ENCRYPTED = "ENCRYPTED";
    private static final String PRIVATE = "PRIVATE";
    private static final String PUBLIC_KEY_EXTENSION = "pub";
    /**
     * Au-delà, les clés d'un même fichier (jeu de vecteurs de test : des milliers de clés Wycheproof) forment un
     * actif par type et algorithme, avec toutes leurs occurrences : l'inventaire reste lisible.
     */
    static final int MAX_KEYS_PER_FILE = 25;

    private final AssetFactory assetFactory;
    private final CertificateFactory certificateFactory;

    public MaterialDetector(AssetFactory assetFactory) {
        this.assetFactory = assetFactory;
        try {
            this.certificateFactory = CertificateFactory.getInstance("X.509");
        } catch (CertificateException e) {
            throw new IllegalStateException("Fabrique X.509 indisponible", e);
        }
    }

    @Override
    public String name() {
        return "matériel";
    }

    @Override
    public DetectionResult detect(DetectionContext context) {
        List<CryptoAsset> assets = new ArrayList<>();
        FileFailures failures = new FileFailures(name());
        for (ScannedFile file : context.scan().files()) {
            Path path = context.projectRoot().resolve(file.path());
            try {
                if (FileClassifier.isArchive(file.path())) {
                    assets.addAll(fromArchive(file.path(), path));
                    continue;
                }
                byte[] bytes = Files.readAllBytes(path);
                if (file.material()) {
                    assets.addAll(fromMaterialFile(file.path(), bytes));
                } else {
                    assets.addAll(fromText(file.path(), new String(bytes, StandardCharsets.UTF_8)));
                }
            } catch (IOException | RuntimeException | StackOverflowError e) {
                failures.record(file.path(), e);
            }
        }
        return new DetectionResult(assets, List.of(), failures.warnings());
    }

    /** Clés et certificats d'une archive versionnée, nommés "archive.zip!/chemin/dans/l/archive". */
    private List<CryptoAsset> fromArchive(String file, Path path) throws IOException {
        List<CryptoAsset> assets = new ArrayList<>();
        ArchiveEntries.forEach(path, entry -> {
            String shown = file + ArchiveEntries.SEPARATOR + entry.path();
            String name = shown.substring(shown.lastIndexOf('/') + 1);
            if (FileClassifier.isMaterial(name)) {
                assets.addAll(fromMaterialFile(shown, entry.content()));
            } else if (FileClassifier.isScanned(name)) {
                assets.addAll(fromText(shown, new String(entry.content(), StandardCharsets.UTF_8)));
            }
        });
        return assets;
    }

    private List<CryptoAsset> fromMaterialFile(String file, byte[] bytes) {
        String extension = FileClassifier.extension(file).orElse("");
        if (KEYSTORE_EXTENSIONS.contains(extension)) {
            return List.of(assetFactory.material(file, MaterialInfo.of("keystore", extension.toUpperCase(Locale.ROOT)),
                    null, occurrence(file, null, null)));
        }
        String text = new String(bytes, StandardCharsets.US_ASCII);
        if (text.contains(PEM_MARKER)) {
            return fromPem(file, text, null, 0, null);
        }
        Matcher ssh = SSH_PUBLIC_KEY.matcher(text);
        if (ssh.find()) {
            return List.of(sshPublicKey(file, ssh.group(1), ssh.group(2)));
        }
        if (text.startsWith("PuTTY-User-Key-File")) {
            return List.of(assetFactory.material(file, MaterialInfo.of("private-key", "PPK"), null,
                    occurrence(file, 1, null)));
        }
        if (DER_CERT_EXTENSIONS.contains(extension)) {
            return parseCertificate(bytes)
                    .map(cert -> List.of(certificate(file, 0, cert, "DER", 1)))
                    .orElse(List.of());
        }
        // Contenu illisible : une clé publique si l'extension le dit, sinon une clé à identifier (peut-être privée).
        String type = PUBLIC_KEY_EXTENSION.equals(extension) ? "public-key" : AssetFactory.UNIDENTIFIED_KEY;
        return List.of(assetFactory.material(file, MaterialInfo.of(type, extension.toUpperCase(Locale.ROOT)), null,
                occurrence(file, null, null)));
    }

    /** Matériel écrit dans un fichier de code, de configuration ou de données. */
    private List<CryptoAsset> fromText(String file, String text) {
        List<CryptoAsset> assets = new ArrayList<>();
        if (text.contains(PEM_MARKER)) {
            assets.addAll(fromPem(file, text, "embarqué", 0, null));
        }
        if (text.contains(BASE64_PEM_MARKER)) {
            Matcher encoded = BASE64_PEM.matcher(text);
            while (encoded.find()) {
                Optional<String> pem = decode(encoded.group()).map(b -> new String(b, StandardCharsets.US_ASCII));
                if (pem.isPresent()) {
                    assets.addAll(fromPem(file, pem.get(), "Base64", assets.size(), lineOf(text, encoded.start())));
                }
            }
        }
        if (text.contains(JWK_MARKER)) {
            Matcher jwk = JWK.matcher(text);
            while (jwk.find()) {
                assets.add(jwk(file, jwk.group(), jwk.group("kty"), assets.size(), lineOf(text, jwk.start())));
            }
        }
        return grouped(assets);
    }

    /** Clés d'un fichier qui en contient beaucoup : une par type et algorithme ; les certificats restent un à un. */
    private static List<CryptoAsset> grouped(List<CryptoAsset> assets) {
        if (assets.size() <= MAX_KEYS_PER_FILE) {
            return assets;
        }
        Map<String, CryptoAsset> groups = new LinkedHashMap<>();
        for (CryptoAsset asset : assets) {
            String key = asset.material() == null ? asset.bomRef()
                    : asset.material().materialType() + "|" + (asset.algorithm() == null ? "" : asset.algorithm().displayName());
            groups.merge(key, asset, (first, next) -> {
                List<Occurrence> occurrences = new ArrayList<>(first.occurrences());
                occurrences.addAll(next.occurrences());
                return new CryptoAsset(first.bomRef(), first.name(), first.assetType(), first.algorithm(),
                        first.material(), first.description(), first.functions(), first.sources(), occurrences,
                        first.verdict());
            });
        }
        return List.copyOf(groups.values());
    }

    /** JWK : clé privée si elle porte "d" (secrète pour "oct"), publique sinon ; RSA mesurée sur son module. */
    private CryptoAsset jwk(String file, String json, String kty, int index, int line) {
        boolean privatePart = JWK_PRIVATE_PART.matcher(json).find();
        String type = "oct".equals(kty) ? "secret-key" : privatePart ? "private-key" : "public-key";
        AlgorithmSpec spec = null;
        Matcher curve = JWK_CURVE.matcher(json);
        Matcher modulus = JWK_MODULUS.matcher(json);
        if ("RSA".equals(kty)) {
            spec = assetFactory.normalizer().normalize("RSA");
            if (modulus.find()) {
                spec = spec.withKeySize(modulus.group(1).length() * 6 / Byte.SIZE * Byte.SIZE);
            }
        } else if (curve.find()) {
            spec = assetFactory.normalizer().normalize(("EC".equals(kty) ? "EC-" : "") + curve.group(1));
        }
        return assetFactory.material(file + (index > 0 ? "#" + index : ""), MaterialInfo.of(type, "JWK"), spec,
                occurrence(file, line, "kty " + kty));
    }

    /**
     * @param firstIndex numéro du premier élément (plusieurs blocs dans un même fichier)
     * @param fixedLine  ligne à attribuer à tous les blocs (PEM décodé d'une valeur Base64), null pour la calculer
     */
    private List<CryptoAsset> fromPem(String file, String text, String formatSuffix, int firstIndex, Integer fixedLine) {
        List<CryptoAsset> assets = new ArrayList<>();
        int index = firstIndex;
        Matcher header = PEM_HEADER.matcher(text);
        while (header.find()) {
            String type = header.group(1).trim();
            int line = fixedLine != null ? fixedLine : lineOf(text, header.start());
            Matcher block = PEM_BLOCK.matcher(text);
            String body = block.find(header.start()) && block.start() == header.start() ? block.group(2) : null;
            String format = "PEM" + (formatSuffix == null ? "" : " (" + formatSuffix + ")");
            if (type.contains("CERTIFICATE") && !type.contains("REQUEST")) {
                Optional<X509Certificate> cert = decode(body).flatMap(this::parseCertificate);
                if (cert.isPresent()) {
                    assets.add(certificate(file, index, cert.get(), format, line));
                } else {
                    assets.add(assetFactory.certificate(file, index, null, MaterialInfo.of("certificate", format),
                            occurrence(file, line, header.group())));
                }
                index++;
            } else if (type.contains(PRIVATE)) {
                String algorithm = headerAlgorithm(type);
                String privateFormat = type.contains(ENCRYPTED) ? format + " " + ENCRYPTED : format;
                // PKCS#8 ("BEGIN PRIVATE KEY") : l'algorithme et la taille ne sont lisibles que dans la clé.
                AlgorithmSpec spec = type.contains(ENCRYPTED) ? null
                        : decode(body).flatMap(KeyInspector::privateKey)
                                .map(k -> assetFactory.normalizer().normalize(k.algorithm()).withKeySize(k.size()))
                                .orElse(null);
                if (spec == null && algorithm != null) {
                    spec = assetFactory.normalizer().normalize(algorithm);
                }
                assets.add(assetFactory.material(file + (index > 0 ? "#" + index : ""),
                        MaterialInfo.of("private-key", privateFormat), spec, occurrence(file, line, header.group())));
                index++;
            } else if (type.contains("PUBLIC KEY")) {
                AlgorithmSpec spec = decode(body).flatMap(KeyInspector::publicKey)
                        .map(k -> assetFactory.normalizer().normalize(k.algorithm()).withKeySize(k.size()))
                        .orElseGet(() -> Optional.ofNullable(headerAlgorithm(type))
                                .map(assetFactory.normalizer()::normalize).orElse(null));
                assets.add(assetFactory.material(file + (index > 0 ? "#" + index : ""),
                        MaterialInfo.of("public-key", format), spec, occurrence(file, line, header.group())));
                index++;
            }
        }
        return assets;
    }

    private CryptoAsset certificate(String file, int index, X509Certificate cert, String format, int line) {
        AlgorithmSpec spec = assetFactory.normalizer().normalize(cert.getSigAlgName());
        Optional<KeyInspector.KeyInfo> key = KeyInspector.describe(cert.getPublicKey());
        if (key.isPresent() && spec.keySize() == null && key.get().size() != null) {
            spec = spec.withKeySize(key.get().size());
        }
        MaterialInfo material = new MaterialInfo("certificate", format,
                cert.getSubjectX500Principal().getName(), cert.getIssuerX500Principal().getName(),
                cert.getNotBefore().toInstant().toString(), cert.getNotAfter().toInstant().toString(), false);
        return assetFactory.certificate(file, index, spec, material, occurrence(file, line, cert.getSigAlgName()));
    }

    private CryptoAsset sshPublicKey(String file, String type, String blob) {
        String algorithm = SSH_ALGORITHMS.get(type);
        AlgorithmSpec spec = assetFactory.normalizer().normalize(algorithm);
        if ("ssh-rsa".equals(type)) {
            Integer size = KeyInspector.sshRsaModulusBits(blob);
            if (size != null) {
                spec = spec.withKeySize(size);
            }
        }
        return assetFactory.material(file, MaterialInfo.of("public-key", "OpenSSH"), spec, occurrence(file, 1, type));
    }

    private Optional<X509Certificate> parseCertificate(byte[] der) {
        try {
            return Optional.of((X509Certificate) certificateFactory.generateCertificate(new ByteArrayInputStream(der)));
        } catch (CertificateException | ClassCastException e) {
            LOG.debug("Certificat illisible", e);
            return Optional.empty();
        }
    }

    private static Optional<byte[]> decode(String body) {
        if (body == null) {
            return Optional.empty();
        }
        String cleaned = body.replace("\\n", "").replaceAll("(?m)^[A-Za-z-]+:.*$", "").replaceAll("\\s", "");
        try {
            return cleaned.isEmpty() ? Optional.empty() : Optional.of(Base64.getDecoder().decode(cleaned));
        } catch (IllegalArgumentException e) {
            return Optional.empty();
        }
    }

    private static String headerAlgorithm(String type) {
        for (String algorithm : List.of("RSA", "DSA", "EC", "OPENSSH")) {
            if (type.startsWith(algorithm + " ")) {
                return "OPENSSH".equals(algorithm) ? null : algorithm;
            }
        }
        return null;
    }

    private static Occurrence occurrence(String file, Integer line, String snippet) {
        return new Occurrence(file, line, null, null, snippet, null, DetectionSource.MATERIAL, "material", Set.of());
    }

    private static int lineOf(String text, int offset) {
        int line = 1;
        for (int i = 0; i < offset; i++) {
            if (text.charAt(i) == '\n') {
                line++;
            }
        }
        return line;
    }
}
