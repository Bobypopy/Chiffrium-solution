package com.chiffrium.infrastructure.crypto;

import com.chiffrium.application.security.SetupTokenStore;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Optional;

/**
 * Jeton d'installation stocké dans {@code <DATA_DIR>/secrets/setup-token} (droits restreints) et affiché
 * dans les logs au démarrage. L'application de bureau le lit directement pour une installation transparente.
 */
public final class FileSetupTokenStore implements SetupTokenStore {

    private static final Logger LOG = LoggerFactory.getLogger(FileSetupTokenStore.class);
    private static final String FILE_NAME = "setup-token";
    private static final int TOKEN_BYTES = 24;

    private final Path file;

    public FileSetupTokenStore(Path secretsDir) {
        this.file = secretsDir.resolve(FILE_NAME);
    }

    @Override
    public synchronized Optional<String> current() {
        try {
            if (Files.exists(file)) {
                return Optional.of(Files.readString(file).trim());
            }
            Files.createDirectories(file.getParent());
            byte[] bytes = new byte[TOKEN_BYTES];
            new SecureRandom().nextBytes(bytes);
            String token = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
            Files.writeString(file, token);
            SecureFiles.restrictToOwner(file);
            return Optional.of(token);
        } catch (IOException e) {
            throw new UncheckedIOException("Jeton d'installation inaccessible : " + file, e);
        }
    }

    @Override
    public synchronized void consume() {
        try {
            Files.deleteIfExists(file);
        } catch (IOException e) {
            LOG.warn("Suppression du jeton d'installation impossible : {}", file, e);
        }
    }

    /** Annonce le jeton dans les logs quand l'installation n'est pas encore faite. */
    public void announce() {
        current().ifPresent(token -> LOG.warn(
                "Première installation : créer le compte administrateur avec le jeton d'installation {} "
                        + "(également dans {}).", token, file));
    }
}
