package com.chiffrium.infrastructure.crypto;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HexFormat;
import java.util.Optional;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Clé maîtresse de l'instance (256 bits), dont dérivent la clé de chiffrement de la base et celle des
 * artefacts. Source, par ordre de priorité :
 * <ol>
 *   <li>variable d'environnement {@code MASTER_KEY} (Base64) - recommandé en production (secret Kubernetes, coffre) ;</li>
 *   <li>fichier {@code <DATA_DIR>/secrets/master.key}, créé au premier démarrage avec des droits restreints au
 *       propriétaire - pratique pour l'application de bureau.</li>
 * </ol>
 * Perdre cette clé rend les données illisibles : elle doit être sauvegardée séparément des données.
 */
public final class MasterKey {

    public static final int KEY_BYTES = 32;
    private static final String KEY_FILE = "master.key";
    private static final String HMAC_ALGORITHM = "HmacSHA256";
    private static final byte HKDF_FIRST_BLOCK = 0x01;

    private final byte[] key;

    private MasterKey(byte[] key) {
        if (key.length != KEY_BYTES) {
            throw new IllegalStateException("La clé maîtresse doit faire " + KEY_BYTES + " octets.");
        }
        this.key = key.clone();
    }

    public static MasterKey load(Optional<String> fromEnvironment, Path secretsDir) {
        if (fromEnvironment.isPresent()) {
            return new MasterKey(Base64.getDecoder().decode(fromEnvironment.get().trim()));
        }
        Path file = secretsDir.resolve(KEY_FILE);
        try {
            if (Files.exists(file)) {
                return new MasterKey(Base64.getDecoder().decode(Files.readString(file).trim()));
            }
            Files.createDirectories(secretsDir);
            SecureFiles.restrictToOwner(secretsDir);
            byte[] generated = new byte[KEY_BYTES];
            new SecureRandom().nextBytes(generated);
            Files.writeString(file, Base64.getEncoder().encodeToString(generated));
            SecureFiles.restrictToOwner(file);
            return new MasterKey(generated);
        } catch (IOException e) {
            throw new UncheckedIOException("Clé maîtresse inaccessible : " + file, e);
        }
    }

    /**
     * Sous-clé dédiée à un usage (séparation des clés : base, artefacts...), calculée comme
     * HMAC-SHA256(clé maîtresse, usage || 0x01), soit une expansion HKDF (RFC 5869) d'un bloc.
     */
    public byte[] derive(String purpose) {
        try {
            Mac mac = Mac.getInstance(HMAC_ALGORITHM);
            mac.init(new SecretKeySpec(key, HMAC_ALGORITHM));
            mac.update(purpose.getBytes(StandardCharsets.UTF_8));
            mac.update(HKDF_FIRST_BLOCK);
            return mac.doFinal();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(HMAC_ALGORITHM + " indisponible", e);
        }
    }

    public String deriveHex(String purpose) {
        return HexFormat.of().formatHex(derive(purpose));
    }
}
