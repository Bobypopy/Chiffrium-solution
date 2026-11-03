package com.chiffrium.infrastructure.binary;

import com.chiffrium.domain.model.CryptoFunction;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

/**
 * Signatures du code compilé ({@code resources/binary/signatures.json}) : comme les règles, ajouter un nom ne
 * demande aucun code Java. Une signature invalide empêche le démarrage.
 */
public final class BinarySignatures {

    private static final String RESOURCE = "/binary/signatures.json";

    /**
     * @param pattern   expression appliquée à chaque chaîne extraite, groupe {@code name} obligatoire
     * @param map       correspondance de noms (clés en minuscules)
     * @param functions  opérations réalisées
     * @param extensions extensions de fichier où la signature vaut (vide : tous les binaires) ; "md5" seul ne dit
     *                   quelque chose que dans du bytecode Python
     */
    public record Signature(String id, Pattern pattern, Map<String, String> map, List<CryptoFunction> functions,
                            List<String> extensions) {

        String mapped(String name) {
            return map.getOrDefault(name.toLowerCase(Locale.ROOT), name);
        }

        boolean appliesTo(String file) {
            String lower = file.toLowerCase(Locale.ROOT);
            return extensions.isEmpty() || extensions.stream().anyMatch(e -> lower.endsWith("." + e));
        }
    }

    private BinarySignatures() {
    }

    public static List<Signature> loadBuiltIn(ObjectMapper mapper) {
        try (InputStream in = BinarySignatures.class.getResourceAsStream(RESOURCE)) {
            if (in == null) {
                throw new IllegalStateException("Ressource manquante : " + RESOURCE);
            }
            List<Signature> signatures = new ArrayList<>();
            for (JsonNode node : mapper.readTree(in).path("signatures")) {
                String id = node.path("id").asText();
                Pattern pattern;
                try {
                    pattern = Pattern.compile(node.path("pattern").asText());
                } catch (PatternSyntaxException e) {
                    throw new IllegalStateException(RESOURCE + " / " + id + " : expression invalide", e);
                }
                if (!pattern.namedGroups().containsKey("name")) {
                    throw new IllegalStateException(RESOURCE + " / " + id + " : groupe name manquant");
                }
                Map<String, String> map = new LinkedHashMap<>();
                node.path("map").properties().forEach(e -> map.put(e.getKey().toLowerCase(Locale.ROOT), e.getValue().asText()));
                List<CryptoFunction> functions = new ArrayList<>();
                node.path("functions").forEach(f -> functions.add(CryptoFunction.fromCycloneDx(f.asText())));
                List<String> extensions = new ArrayList<>();
                node.path("extensions").forEach(e -> extensions.add(e.asText().toLowerCase(Locale.ROOT)));
                signatures.add(new Signature(id, pattern, Map.copyOf(map), List.copyOf(functions),
                        List.copyOf(extensions)));
            }
            return List.copyOf(signatures);
        } catch (IOException e) {
            throw new UncheckedIOException("Signatures illisibles : " + RESOURCE, e);
        }
    }
}
