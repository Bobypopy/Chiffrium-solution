package com.chiffrium.domain.model;

import com.fasterxml.jackson.annotation.JsonValue;

import java.util.List;
import java.util.Locale;

/**
 * Graphe reliant fonctions, API cryptographiques, actifs et fichiers de clés.
 * Il est construit côté serveur pour que l'interface n'ait qu'à l'afficher.
 */
public record CallGraph(List<Node> nodes, List<Edge> edges) {

    public CallGraph {
        nodes = nodes == null ? List.of() : List.copyOf(nodes);
        edges = edges == null ? List.of() : List.copyOf(edges);
    }

    public static CallGraph empty() {
        return new CallGraph(List.of(), List.of());
    }

    public enum NodeKind {
        FUNCTION, CRYPTO_API, ASSET, FILE;

        @JsonValue
        public String id() {
            return name().toLowerCase(Locale.ROOT);
        }
    }

    public enum EdgeKind {
        /** Une fonction en appelle une autre. */
        CALLS,
        /** Une fonction utilise un actif cryptographique. */
        USES,
        /** Une fonction écrit un fichier de matériel cryptographique. */
        PRODUCES,
        /** Une fonction lit un fichier de matériel cryptographique. */
        CONSUMES;

        @JsonValue
        public String id() {
            return name().toLowerCase(Locale.ROOT);
        }
    }

    /**
     * @param id       identifiant unique dans le graphe
     * @param label    libellé court
     * @param kind     nature du nœud
     * @param file     fichier source (fonctions)
     * @param line     ligne (fonctions)
     * @param assetRef bom-ref de l'actif (nœuds ASSET)
     */
    public record Node(String id, String label, NodeKind kind, String file, Integer line, String assetRef) {
    }

    public record Edge(String from, String to, EdgeKind kind) {
    }
}
