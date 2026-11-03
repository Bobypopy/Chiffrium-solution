package com.chiffrium.infrastructure.cdxgen;

import com.chiffrium.application.port.CallEdgeExtractor;
import com.chiffrium.application.port.SbomGenerator.SbomResult;
import com.chiffrium.infrastructure.json.JsonNodes;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

/**
 * Lit les slices "usages" d'atom : pour chaque méthode (objectSlices[].fullName), les appels
 * effectués sont dans usages[].invokedCalls (appels sur un objet, ex. Cipher.init) et
 * usages[].argToCalls (objet passé en argument). L'ancienne version ignorait invokedCalls, qui
 * contient pourtant la majorité des appels aux API cryptographiques.
 */
public final class SliceCallEdgeExtractor implements CallEdgeExtractor {

    private static final Logger LOG = LoggerFactory.getLogger(SliceCallEdgeExtractor.class);
    private static final List<String> CALL_ARRAYS = List.of("invokedCalls", "argToCalls");

    private final ObjectMapper mapper;

    public SliceCallEdgeExtractor(ObjectMapper mapper) {
        this.mapper = mapper;
    }

    @Override
    public List<CallEdge> extract(SbomResult sbom) {
        Map<String, CallEdge> edges = new LinkedHashMap<>();
        for (Path slice : sbom.usagesSlices().values()) {
            try {
                JsonNode root = mapper.readTree(slice.toFile());
                JsonNodes.array(root, "objectSlices").forEach(method -> collect(method, edges));
            } catch (IOException e) {
                LOG.warn("Slice d'usages illisible : {}", slice, e);
            }
        }
        return List.copyOf(edges.values());
    }

    private static void collect(JsonNode method, Map<String, CallEdge> edges) {
        String caller = JsonNodes.text(method, "fullName");
        String file = CdxgenCryptoDetector.normalizePath(JsonNodes.text(method, "fileName"));
        if (caller == null) {
            return;
        }
        JsonNodes.array(method, "usages")
                .flatMap(usage -> CALL_ARRAYS.stream().flatMap(field -> JsonNodes.array(usage, field)))
                .flatMap(call -> toEdge(caller, file, call))
                .forEach(edge -> edges.putIfAbsent(edge.caller() + "->" + edge.callee(), edge));
    }

    private static Stream<CallEdge> toEdge(String caller, String file, JsonNode call) {
        String callee = JsonNodes.text(call, "resolvedMethod");
        if (callee == null || callee.equals(caller)) {
            return Stream.empty();
        }
        return Stream.of(new CallEdge(caller, callee, file, JsonNodes.integer(call, "lineNumber"),
                JsonNodes.bool(call, "isExternal")));
    }
}
