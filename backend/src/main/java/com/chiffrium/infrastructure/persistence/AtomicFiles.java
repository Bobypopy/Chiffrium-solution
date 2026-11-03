package com.chiffrium.infrastructure.persistence;

import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;

/**
 * Écriture atomique : le fichier cible n'est jamais lu à moitié écrit, même en cas d'arrêt brutal.
 */
final class AtomicFiles {

    private static final String TEMP_SUFFIX = ".tmp";

    private AtomicFiles() {
    }

    static void writeJson(ObjectMapper mapper, Path target, Object value) {
        try {
            writeBytes(target, mapper.writerWithDefaultPrettyPrinter().writeValueAsBytes(value));
        } catch (IOException e) {
            throw new UncheckedIOException("Sérialisation impossible : " + target, e);
        }
    }

    static void writeBytes(Path target, byte[] content) {
        try {
            Files.createDirectories(target.getParent());
            Path temp = target.resolveSibling(target.getFileName() + TEMP_SUFFIX);
            Files.write(temp, content);
            try {
                Files.move(temp, target, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
            } catch (AtomicMoveNotSupportedException e) {
                Files.move(temp, target, StandardCopyOption.REPLACE_EXISTING);
            }
        } catch (IOException e) {
            throw new UncheckedIOException("Écriture impossible : " + target, e);
        }
    }
}
