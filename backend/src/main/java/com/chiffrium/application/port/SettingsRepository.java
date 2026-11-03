package com.chiffrium.application.port;

import com.chiffrium.application.settings.Settings;

import java.util.Optional;

/**
 * Persistance des paramètres modifiables par un administrateur. Les secrets qu'ils contiennent sont
 * chiffrés par l'implémentation.
 */
public interface SettingsRepository {

    Optional<Settings> load();

    void save(Settings settings);
}
