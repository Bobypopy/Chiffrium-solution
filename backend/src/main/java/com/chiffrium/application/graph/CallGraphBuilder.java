package com.chiffrium.application.graph;

import com.chiffrium.application.port.CallEdgeExtractor.CallEdge;
import com.chiffrium.application.port.CryptoDetector.FileFlow;
import com.chiffrium.domain.model.CallGraph;
import com.chiffrium.domain.model.CallGraph.EdgeKind;
import com.chiffrium.domain.model.CallGraph.NodeKind;
import com.chiffrium.domain.model.CryptoAsset;
import com.chiffrium.domain.model.Occurrence;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * Construit le graphe affiché par l'interface :
 * <ul>
 *   <li>actif <- fonction qui l'utilise (arête USES) ;</li>
 *   <li>fonction -> fichier de clé écrit (PRODUCES) / fichier -> fonction qui le lit (CONSUMES) ;</li>
 *   <li>appelants des fonctions cryptographiques, jusqu'à {@link #MAX_CALLER_DEPTH} niveaux (CALLS) ;</li>
 *   <li>API cryptographiques externes appelées par ces fonctions (CALLS vers CRYPTO_API).</li>
 * </ul>
 * Les fonctions sont identifiées par "Classe.méthode" (ou "module.fonction") afin de relier les
 * détections du moteur de règles et les appels issus des slices cdxgen.
 */
public final class CallGraphBuilder {

    static final int MAX_CALLER_DEPTH = 3;
    /**
     * Garde-fou contre un rapport démesuré. L'interface n'affiche de toute façon qu'une vue partielle des gros
     * graphes (actifs les plus risqués, recherche) : tronquer ici rendait des fonctions introuvables.
     */
    static final int MAX_NODES = 5_000;

    /** Préfixes d'API considérées comme cryptographiques lorsqu'elles sont appelées. */
    private static final List<String> CRYPTO_API_HINTS = List.of(
            "cipher", "messagedigest", "mac.", "signature", "keygenerator", "keypairgenerator", "secretkeyfactory",
            "keyagreement", "keyfactory", "securerandom", "sslcontext", "keystore", "hashlib", "hmac", "crypto",
            "bouncycastle", "ssl", "tls");

    private final Map<String, CallGraph.Node> nodes = new LinkedHashMap<>();
    private final Set<CallGraph.Edge> edges = new LinkedHashSet<>();
    private final List<String> warnings = new ArrayList<>();

    public record Result(CallGraph graph, List<String> warnings) {
    }

    public Result build(List<CryptoAsset> assets, List<FileFlow> fileFlows, List<CallEdge> callEdges) {
        Set<String> cryptoFunctions = new HashSet<>();
        for (CryptoAsset asset : assets) {
            String assetNode = "asset:" + asset.bomRef();
            addNode(new CallGraph.Node(assetNode, asset.name(), NodeKind.ASSET, null, null, asset.bomRef()));
            for (Occurrence occurrence : asset.occurrences()) {
                if (occurrence.function() == null) {
                    continue;
                }
                String functionKey = functionKey(occurrence.function());
                String functionNode = addFunction(functionKey, occurrence.file(), occurrence.line());
                cryptoFunctions.add(functionKey);
                edges.add(new CallGraph.Edge(functionNode, assetNode, EdgeKind.USES));
            }
        }
        for (FileFlow flow : fileFlows) {
            String fileNode = "file:" + flow.materialFile();
            addNode(new CallGraph.Node(fileNode, flow.materialFile(), NodeKind.FILE, null, null, null));
            if (flow.function() == null) {
                continue;
            }
            String functionKey = functionKey(flow.function());
            String functionNode = addFunction(functionKey, flow.sourceFile(), flow.line());
            cryptoFunctions.add(functionKey);
            edges.add(flow.produces()
                    ? new CallGraph.Edge(functionNode, fileNode, EdgeKind.PRODUCES)
                    : new CallGraph.Edge(fileNode, functionNode, EdgeKind.CONSUMES));
        }
        addCallers(cryptoFunctions, callEdges);
        addCryptoApis(callEdges);

        List<CallGraph.Node> nodeList = new ArrayList<>(nodes.values());
        List<CallGraph.Edge> edgeList = new ArrayList<>(edges);
        if (nodeList.size() > MAX_NODES) {
            warnings.add("Graphe tronqué à " + MAX_NODES + " nœuds sur " + nodeList.size() + ".");
            nodeList = nodeList.subList(0, MAX_NODES);
            Set<String> kept = new HashSet<>();
            nodeList.forEach(n -> kept.add(n.id()));
            edgeList = edgeList.stream().filter(e -> kept.contains(e.from()) && kept.contains(e.to())).toList();
        }
        return new Result(new CallGraph(nodeList, edgeList), warnings);
    }

    private void addCallers(Set<String> cryptoFunctions, List<CallEdge> callEdges) {
        Map<String, List<CallEdge>> byCallee = new HashMap<>();
        for (CallEdge edge : callEdges) {
            if (!edge.external()) {
                byCallee.computeIfAbsent(functionKey(edge.callee()), k -> new ArrayList<>()).add(edge);
            }
        }
        Deque<String> frontier = new ArrayDeque<>(cryptoFunctions);
        Map<String, Integer> depth = new HashMap<>();
        cryptoFunctions.forEach(f -> depth.put(f, 0));
        while (!frontier.isEmpty()) {
            String callee = frontier.poll();
            int calleeDepth = depth.get(callee);
            if (calleeDepth >= MAX_CALLER_DEPTH) {
                continue;
            }
            for (CallEdge edge : byCallee.getOrDefault(callee, List.of())) {
                String caller = functionKey(edge.caller());
                if (caller.equals(callee)) {
                    continue;
                }
                String callerNode = addFunction(caller, edge.file(), edge.line());
                edges.add(new CallGraph.Edge(callerNode, functionNodeId(callee), EdgeKind.CALLS));
                if (!depth.containsKey(caller)) {
                    depth.put(caller, calleeDepth + 1);
                    frontier.add(caller);
                }
            }
        }
    }

    private void addCryptoApis(List<CallEdge> callEdges) {
        for (CallEdge edge : callEdges) {
            String caller = functionKey(edge.caller());
            if (!edge.external() || !nodes.containsKey(functionNodeId(caller)) || !isCryptoApi(edge.callee())) {
                continue;
            }
            String apiKey = functionKey(edge.callee());
            String apiNode = "api:" + apiKey;
            addNode(new CallGraph.Node(apiNode, apiKey, NodeKind.CRYPTO_API, null, null, null));
            edges.add(new CallGraph.Edge(functionNodeId(caller), apiNode, EdgeKind.CALLS));
        }
    }

    private static boolean isCryptoApi(String callee) {
        String lower = callee.toLowerCase(Locale.ROOT);
        return CRYPTO_API_HINTS.stream().anyMatch(lower::contains);
    }

    private String addFunction(String key, String file, Integer line) {
        String id = functionNodeId(key);
        nodes.putIfAbsent(id, new CallGraph.Node(id, key, NodeKind.FUNCTION, file, line, null));
        return id;
    }

    private void addNode(CallGraph.Node node) {
        nodes.putIfAbsent(node.id(), node);
    }

    private static String functionNodeId(String key) {
        return "fn:" + key;
    }

    /**
     * Réduit un nom qualifié à "Conteneur.fonction" : retire la signature ("decrypt:byte[](byte[])")
     * et le paquet ("com.acme.Crypto.decrypt" devient "Crypto.decrypt").
     */
    static String functionKey(String qualifiedName) {
        String name = qualifiedName;
        int signature = indexOfAny(name, ':', '(');
        if (signature > 0) {
            name = name.substring(0, signature);
        }
        String[] parts = name.split("\\.");
        if (parts.length <= 2) {
            return name;
        }
        return parts[parts.length - 2] + "." + parts[parts.length - 1];
    }

    private static int indexOfAny(String value, char first, char second) {
        int a = value.indexOf(first);
        int b = value.indexOf(second);
        if (a < 0) {
            return b;
        }
        return b < 0 ? a : Math.min(a, b);
    }
}
