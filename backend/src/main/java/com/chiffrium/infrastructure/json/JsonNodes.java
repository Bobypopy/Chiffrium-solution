package com.chiffrium.infrastructure.json;

import com.fasterxml.jackson.databind.JsonNode;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;
import java.util.stream.StreamSupport;

/**
 * Lecture défensive de JSON produit par des outils tiers : champs absents, null, ou de type inattendu
 * (ex. lineNumber null dans les slices atom) ne provoquent jamais d'exception.
 */
public final class JsonNodes {

    private JsonNodes() {
    }

    public static String text(JsonNode node, String field) {
        JsonNode value = node == null ? null : node.get(field);
        if (value == null || value.isNull() || value.isContainerNode()) {
            return null;
        }
        String text = value.asText().trim();
        return text.isEmpty() ? null : text;
    }

    public static Integer integer(JsonNode node, String field) {
        JsonNode value = node == null ? null : node.get(field);
        if (value == null || value.isNull()) {
            return null;
        }
        if (value.canConvertToInt()) {
            int number = value.asInt();
            return number > 0 ? number : null;
        }
        return null;
    }

    public static boolean bool(JsonNode node, String field) {
        JsonNode value = node == null ? null : node.get(field);
        return value != null && value.asBoolean(false);
    }

    /** Éléments d'un tableau ; flux vide si le champ est absent ou n'est pas un tableau. */
    public static Stream<JsonNode> array(JsonNode node, String field) {
        JsonNode value = node == null ? null : node.get(field);
        if (value == null || !value.isArray()) {
            return Stream.empty();
        }
        return StreamSupport.stream(value.spliterator(), false);
    }

    public static List<String> texts(JsonNode node, String field) {
        List<String> result = new ArrayList<>();
        array(node, field).filter(JsonNode::isTextual).map(JsonNode::asText).forEach(result::add);
        return result;
    }
}
