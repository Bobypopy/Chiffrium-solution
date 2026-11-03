package com.chiffrium.infrastructure.material;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.List;
import java.util.Optional;

/**
 * Extrait l'algorithme et la taille d'une clé publique (JCA standard, sans dépendance externe).
 */
final class KeyInspector {

    private static final List<String> KEY_ALGORITHMS = List.of("RSA", "EC", "Ed25519", "Ed448", "X25519", "X448", "DSA");
    private static final int MAX_SSH_FIELD_BYTES = 16_384;

    private KeyInspector() {
    }

    /**
     * @param algorithm nom normalisable (ex. "RSA", "EC-secp256r1")
     * @param size      taille en bits si pertinente
     */
    record KeyInfo(String algorithm, Integer size) {
    }

    static Optional<KeyInfo> publicKey(byte[] encoded) {
        X509EncodedKeySpec spec = new X509EncodedKeySpec(encoded);
        for (String algorithm : KEY_ALGORITHMS) {
            try {
                return describe(KeyFactory.getInstance(algorithm).generatePublic(spec));
            } catch (Exception e) {
                // Essai de l'algorithme suivant : le type de clé n'est pas connu à l'avance.
            }
        }
        return Optional.empty();
    }

    /**
     * Clé privée au format PKCS#8 ("BEGIN PRIVATE KEY") : l'en-tête PEM ne dit pas l'algorithme, il faut
     * décoder la clé. Sans cela, une clé RSA de 1024 bits dans un dépôt passait sans verdict.
     */
    static Optional<KeyInfo> privateKey(byte[] encoded) {
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(encoded);
        for (String algorithm : KEY_ALGORITHMS) {
            try {
                return describe(KeyFactory.getInstance(algorithm).generatePrivate(spec));
            } catch (Exception e) {
                // Essai de l'algorithme suivant : le type de clé n'est pas connu à l'avance.
            }
        }
        return Optional.empty();
    }

    static Optional<KeyInfo> describe(PrivateKey key) {
        if (key instanceof RSAPrivateKey rsa) {
            return Optional.of(new KeyInfo("RSA", rsa.getModulus().bitLength()));
        }
        if (key instanceof ECPrivateKey ec) {
            return Optional.of(new KeyInfo("EC", ec.getParams() == null ? null
                    : ec.getParams().getCurve().getField().getFieldSize()));
        }
        if (key instanceof DSAPrivateKey dsa) {
            return Optional.of(new KeyInfo("DSA", dsa.getParams() == null ? null : dsa.getParams().getP().bitLength()));
        }
        return Optional.of(new KeyInfo(key.getAlgorithm(), null));
    }

    static Optional<KeyInfo> describe(PublicKey key) {
        if (key instanceof RSAPublicKey rsa) {
            return Optional.of(new KeyInfo("RSA", rsa.getModulus().bitLength()));
        }
        if (key instanceof ECPublicKey ec) {
            if (ec.getParams() == null) {
                return Optional.of(new KeyInfo("EC", null));
            }
            String params = ec.getParams().toString();
            String curve = params.contains(" ") ? params.substring(0, params.indexOf(' ')) : params;
            return Optional.of(new KeyInfo("EC-" + curve, ec.getParams().getCurve().getField().getFieldSize()));
        }
        if (key instanceof DSAPublicKey dsa) {
            // Paramètres absents (hérités d'un certificat parent ou clé de test tronquée) : taille inconnue.
            return Optional.of(new KeyInfo("DSA", dsa.getParams() == null ? null : dsa.getParams().getP().bitLength()));
        }
        return Optional.of(new KeyInfo(key.getAlgorithm(), null));
    }

    /**
     * Taille du module d'une clé publique OpenSSH "ssh-rsa" (format RFC 4253 : chaîne, e, n).
     */
    static Integer sshRsaModulusBits(String base64Blob) {
        try (DataInputStream in = new DataInputStream(new ByteArrayInputStream(Base64.getDecoder().decode(base64Blob)))) {
            readField(in);
            readField(in);
            return new BigInteger(1, readField(in)).bitLength();
        } catch (IOException | IllegalArgumentException e) {
            return null;
        }
    }

    private static byte[] readField(DataInputStream in) throws IOException {
        int length = in.readInt();
        if (length < 0 || length > MAX_SSH_FIELD_BYTES) {
            throw new IOException("Champ SSH invalide");
        }
        byte[] field = new byte[length];
        in.readFully(field);
        return field;
    }
}
