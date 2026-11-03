package com.chiffrium.api;

import com.chiffrium.application.settings.Settings;
import io.javalin.Javalin;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;

/**
 * Informations légales, publiques (visibles avant connexion) : licence, composants et données tiers, services
 * externes contactés, organisation responsable et charte d'utilisation.
 */
final class AboutRoutes {

    static final String ABOUT_PATH = "/api/about";

    private final Map<String, Object> product;
    private final Supplier<Settings> settings;
    private final Supplier<List<String>> externalServices;

    /**
     * @param product          version, licence, composants tiers (données statiques)
     * @param settings         paramètres courants (organisation, sources activées)
     * @param externalServices services réseau contactés avec la configuration courante
     */
    AboutRoutes(Map<String, Object> product, Supplier<Settings> settings, Supplier<List<String>> externalServices) {
        this.product = Map.copyOf(product);
        this.settings = settings;
        this.externalServices = externalServices;
    }

    void register(Javalin server) {
        server.get(ABOUT_PATH, ctx -> {
            Map<String, Object> body = new LinkedHashMap<>(product);
            body.put("organization", settings.get().organization());
            body.put("externalServices", externalServices.get());
            ctx.json(body);
        });
    }
}
