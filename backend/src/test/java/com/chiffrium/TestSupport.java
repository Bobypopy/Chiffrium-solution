package com.chiffrium;

import com.chiffrium.domain.asset.AssetFactory;
import com.chiffrium.domain.policy.AlgorithmCatalog;
import com.chiffrium.domain.policy.AlgorithmNormalizer;
import com.chiffrium.infrastructure.crypto.AesGcmSecretCipher;
import com.chiffrium.infrastructure.crypto.MasterKey;
import com.chiffrium.infrastructure.json.JsonMapper;
import com.chiffrium.infrastructure.persistence.FileCatalogRepository;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Arrays;
import java.util.List;

/**
 * Objets partagés par les tests.
 */
public final class TestSupport {

    public static final ObjectMapper MAPPER = JsonMapper.create();
    public static final AlgorithmCatalog CATALOG = FileCatalogRepository.loadDefault(MAPPER);
    public static final AlgorithmNormalizer NORMALIZER = new AlgorithmNormalizer(CATALOG);
    public static final AssetFactory ASSETS = new AssetFactory(NORMALIZER);

    private TestSupport() {
    }

    /** Chiffrement AES-GCM avec une clé fixe (tests uniquement). */
    public static AesGcmSecretCipher cipher() {
        byte[] key = new byte[MasterKey.KEY_BYTES];
        Arrays.fill(key, (byte) 7);
        return new AesGcmSecretCipher(key);
    }

    /** Horloge figée au 1er juillet de l'année donnée. */
    public static Clock clockAt(int year) {
        return Clock.fixed(Instant.parse(year + "-07-01T00:00:00Z"), ZoneOffset.UTC);
    }

    public static Path fixture(String relative) {
        try {
            return Path.of(TestSupport.class.getResource("/fixtures/" + relative).toURI());
        } catch (URISyntaxException e) {
            throw new IllegalStateException(e);
        }
    }

    public static List<String> lines(Path file) {
        try {
            return Files.readAllLines(file);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    public static Path write(Path root, String relative, String content) {
        try {
            Path file = root.resolve(relative);
            Files.createDirectories(file.getParent());
            Files.writeString(file, content);
            return file;
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }
}
