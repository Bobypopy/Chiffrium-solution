package com.chiffrium.infrastructure.material;

import com.chiffrium.application.port.CryptoDetector;
import com.chiffrium.application.port.ProjectScanner.ScannedFile;
import com.chiffrium.domain.asset.AssetFactory;
import com.chiffrium.domain.model.AlgorithmSpec;
import com.chiffrium.domain.model.CryptoAsset;
import com.chiffrium.domain.model.DetectionSource;
import com.chiffrium.domain.model.MaterialInfo;
import com.chiffrium.domain.model.Occurrence;
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
 *   <li>keystores (PKCS#12, JKS, BKS) signalés sans être ouverts (mot de passe inconnu).</li>
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
    private static final String ENCRYPTED = "ENCRYPTED";
    private static final String PRIVATE = "PRIVATE";

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
                byte[] bytes = Files.readAllBytes(path);
                if (file.material()) {
                    assets.addAll(fromMaterialFile(file.path(), bytes));
                } else {
                    assets.addAll(fromEmbeddedPem(file, new String(bytes, StandardCharsets.UTF_8)));
                }
            } catch (IOException | RuntimeException | StackOverflowError e) {
                failures.record(file.path(), e);
            }
        }
        return new DetectionResult(assets, List.of(), failures.warnings());
    }

    private List<CryptoAsset> fromMaterialFile(String file, byte[] bytes) {
        String extension = FileClassifier.extension(file).orElse("");
        if (KEYSTORE_EXTENSIONS.contains(extension)) {
            return List.of(assetFactory.material(file, MaterialInfo.of("keystore", extension.toUpperCase(Locale.ROOT)),
                    null, occurrence(file, null, null)));
        }
        String text = new String(bytes, StandardCharsets.US_ASCII);
        if (text.contains(PEM_MARKER)) {
            return fromPem(file, text, null);
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
        return List.of(assetFactory.material(file, MaterialInfo.of("key", extension.toUpperCase(Locale.ROOT)), null,
                occurrence(file, null, null)));
    }

    private List<CryptoAsset> fromEmbeddedPem(ScannedFile file, String text) {
        if (!text.contains(PEM_MARKER)) {
            return List.of();
        }
        return fromPem(file.path(), text, "embarqué");
    }

    private List<CryptoAsset> fromPem(String file, String text, String formatSuffix) {
        List<CryptoAsset> assets = new ArrayList<>();
        int index = 0;
        Matcher header = PEM_HEADER.matcher(text);
        while (header.find()) {
            String type = header.group(1).trim();
            int line = lineOf(text, header.start());
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
