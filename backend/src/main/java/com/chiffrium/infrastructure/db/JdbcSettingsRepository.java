package com.chiffrium.infrastructure.db;

import com.chiffrium.application.port.SecretCipher;
import com.chiffrium.application.port.SettingsRepository;
import com.chiffrium.application.settings.Settings;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.util.Optional;

/**
 * Paramètres stockés comme un document JSON chiffré (AES-GCM) : les secrets (clé NVD, secret SSO)
 * ne sont jamais en clair, même dans le fichier de base.
 */
public final class JdbcSettingsRepository implements SettingsRepository {

    private static final int SINGLETON_ID = 1;

    private final Jdbc jdbc;
    private final SecretCipher cipher;
    private final ObjectMapper mapper;

    public JdbcSettingsRepository(Database database, SecretCipher cipher, ObjectMapper mapper) {
        this.jdbc = new Jdbc(database);
        this.cipher = cipher;
        this.mapper = mapper;
    }

    @Override
    public Optional<Settings> load() {
        return jdbc.queryOne("SELECT document FROM settings WHERE id = ?", rs -> rs.getBytes(1), SINGLETON_ID)
                .map(bytes -> {
                    try {
                        return mapper.readValue(cipher.decrypt(bytes), Settings.class);
                    } catch (IOException e) {
                        throw new UncheckedIOException("Paramètres illisibles", e);
                    }
                });
    }

    @Override
    public void save(Settings settings) {
        try {
            byte[] document = cipher.encrypt(mapper.writeValueAsBytes(settings));
            jdbc.upsert("settings", "id", "id, document", SINGLETON_ID, document);
        } catch (IOException e) {
            throw new UncheckedIOException("Paramètres non sérialisables", e);
        }
    }
}
