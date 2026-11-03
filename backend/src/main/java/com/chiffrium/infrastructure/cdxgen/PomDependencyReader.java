package com.chiffrium.infrastructure.cdxgen;

import com.chiffrium.infrastructure.cdxgen.DeclaredDependencies.Dependency;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.xml.sax.helpers.DefaultHandler;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Files;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Dépendances directes déclarées dans les pom.xml, lues sans lancer Maven.
 *
 * <p>Pour lister les dépendances, cdxgen exécute Maven, et d'abord le wrapper {@code mvnw} du dépôt s'il
 * existe : c'est du code du dépôt analysé. Quand l'exécution des outils de build est désactivée, Maven est
 * exclu de cdxgen et ce lecteur le remplace. Les dépendances directes viennent des pom.xml du dépôt ; les
 * transitives sont complétées par {@link #transitive} à partir du cache Maven local quand il est présent.
 * Voir aussi {@link GradleDependencyReader}.
 */
final class PomDependencyReader {

    private static final Logger LOG = LoggerFactory.getLogger(PomDependencyReader.class);
    private static final String POM = "pom.xml";
    private static final Pattern PROPERTY = Pattern.compile("\\$\\{([^}]+)}");
    /** Portées Maven hors exécution : CycloneDX les note "optional", comme cdxgen. */
    private static final Set<String> OPTIONAL_SCOPES = Set.of("test", "provided", "system");
    /** Portées qui se propagent aux dépendances des dépendances (les autres s'arrêtent au premier niveau). */
    private static final Set<String> TRANSITIVE_SCOPES = Set.of("compile", "runtime");
    /** Bornes : un arbre pathologique ne doit ni saturer la mémoire ni faire durer l'analyse. */
    private static final int MAX_TRANSITIVE = 800;
    private static final int MAX_INHERITANCE = 6;

    private PomDependencyReader() {
    }

    /** Dépendances de tous les pom.xml du projet, dédoublonnées (clé : purl). */
    static Map<String, Dependency> read(Path projectRoot) throws IOException {
        List<Pom> poms = new ArrayList<>();
        for (Path file : DeclaredDependencies.files(projectRoot, POM::equals)) {
            try {
                poms.add(Pom.parse(secureBuilder().parse(file.toFile())));
            } catch (Exception e) {
                LOG.debug("pom.xml illisible, ignoré : {}", file, e);
            }
        }
        // Propriétés et versions gérées d'un pom parent du même dépôt : repli quand le pom ne les définit pas.
        Map<String, String> sharedProperties = new HashMap<>();
        Map<String, String> sharedManaged = new HashMap<>();
        poms.forEach(pom -> {
            pom.properties().forEach(sharedProperties::putIfAbsent);
            pom.managed().forEach(sharedManaged::putIfAbsent);
        });
        Map<String, Dependency> result = new LinkedHashMap<>();
        for (Pom pom : poms) {
            for (Map<String, String> declared : pom.dependencies()) {
                String groupId = resolve(declared.get("groupId"), pom.properties(), sharedProperties);
                String artifactId = resolve(declared.get("artifactId"), pom.properties(), sharedProperties);
                if (groupId == null || artifactId == null) {
                    continue;
                }
                String key = groupId + ":" + artifactId;
                String version = declared.get("version");
                if (version == null) {
                    version = pom.managed().getOrDefault(key, sharedManaged.get(key));
                }
                version = resolve(version, pom.properties(), sharedProperties);
                String scope = declared.getOrDefault("scope", "compile");
                Dependency dependency = new Dependency(groupId, artifactId, version,
                        OPTIONAL_SCOPES.contains(scope) || "true".equals(declared.get("optional")));
                DeclaredDependencies.add(result, dependency);
            }
        }
        return result;
    }

    /**
     * Complète l'arbre avec les dépendances transitives trouvées dans un cache Maven local.
     *
     * <p>Aucune exécution ni téléchargement : on lit les pom.xml déjà présents dans le cache. Un cache absent
     * ou incomplet n'est pas une erreur, on rend simplement ce qui a pu être résolu. Les portées test et
     * provided ne sont pas transitives en Maven, elles ne sont donc pas suivies.
     *
     * @param direct     dépendances directes du projet
     * @param repository racine du cache (typiquement {@code ~/.m2/repository})
     * @return les dépendances transitives seules (clé : purl), sans les directes
     */
    static Map<String, Dependency> transitive(Map<String, Dependency> direct, Path repository) {
        Map<String, Dependency> result = new LinkedHashMap<>();
        if (repository == null || !Files.isDirectory(repository)) {
            return result;
        }
        Set<String> seen = new HashSet<>();
        Deque<String> queue = new ArrayDeque<>();
        direct.values().stream()
                .filter(d -> !d.optional() && d.version() != null && "maven".equals(d.ecosystem()))
                .forEach(d -> {
                    String coordinates = d.groupId() + ":" + d.artifactId() + ":" + d.version();
                    seen.add(coordinates);
                    queue.add(coordinates);
                });
        Map<String, Pom> cache = new HashMap<>();
        while (!queue.isEmpty() && result.size() < MAX_TRANSITIVE) {
            Pom pom = load(queue.poll(), repository, cache, 0);
            if (pom == null) {
                continue;
            }
            for (Map<String, String> declared : pom.dependencies()) {
                String scope = declared.getOrDefault("scope", "compile");
                if (!TRANSITIVE_SCOPES.contains(scope) || "true".equals(declared.get("optional"))) {
                    continue;
                }
                String groupId = resolve(declared.get("groupId"), pom.properties(), Map.of());
                String artifactId = resolve(declared.get("artifactId"), pom.properties(), Map.of());
                if (groupId == null || artifactId == null) {
                    continue;
                }
                String version = declared.get("version");
                if (version == null) {
                    version = pom.managed().get(groupId + ":" + artifactId);
                }
                version = resolve(version, pom.properties(), Map.of());
                if (version == null) {
                    continue;
                }
                String coordinates = groupId + ":" + artifactId + ":" + version;
                Dependency dependency = new Dependency(groupId, artifactId, version, false);
                if (direct.containsKey(dependency.purl()) || !seen.add(coordinates)) {
                    continue;
                }
                DeclaredDependencies.add(result, dependency);
                queue.add(coordinates);
            }
        }
        return result;
    }

    /** Pom du cache, parents et BOM importés fusionnés ; {@code null} si absent ou illisible. */
    private static Pom load(String coordinates, Path repository, Map<String, Pom> cache, int depth) {
        if (coordinates == null || depth > MAX_INHERITANCE) {
            return null;
        }
        Pom known = cache.get(coordinates);
        if (known != null || cache.containsKey(coordinates)) {
            return known;
        }
        cache.put(coordinates, null); // Garde-fou : un cycle parent/enfant ne doit pas boucler.
        String[] parts = coordinates.split(":");
        Pom pom = null;
        if (parts.length == 3) {
            Path file = repository.resolve(parts[0].replace('.', '/'))
                    .resolve(parts[1]).resolve(parts[2]).resolve(parts[1] + "-" + parts[2] + ".pom");
            if (Files.isRegularFile(file)) {
                try {
                    pom = Pom.parse(secureBuilder().parse(file.toFile()));
                } catch (Exception e) {
                    LOG.debug("pom.xml du cache illisible, ignoré : {}", file, e);
                }
            }
        }
        if (pom != null) {
            pom = inherited(pom, repository, cache, depth);
            cache.put(coordinates, pom);
        }
        return pom;
    }

    /** Fusionne les propriétés et versions gérées du parent puis des BOM importés (le pom le plus proche gagne). */
    private static Pom inherited(Pom pom, Path repository, Map<String, Pom> cache, int depth) {
        Map<String, String> properties = new HashMap<>(pom.properties());
        Map<String, String> managed = new HashMap<>(pom.managed());
        Pom parent = load(pom.parent(), repository, cache, depth + 1);
        if (parent != null) {
            parent.properties().forEach(properties::putIfAbsent);
            parent.managed().forEach(managed::putIfAbsent);
        }
        for (String imported : pom.managedImports()) {
            String coordinates = resolve(imported, properties, Map.of());
            Pom bom = load(coordinates, repository, cache, depth + 1);
            if (bom != null) {
                bom.properties().forEach(properties::putIfAbsent);
                bom.managed().forEach(managed::putIfAbsent);
            }
        }
        return new Pom(properties, managed, pom.managedImports(), pom.parent(), pom.dependencies());
    }

    /** Parseur sans DTD ni entité externe (XXE) : un pom.xml piégé ne peut ni lire de fichier ni appeler le réseau. */
    static DocumentBuilder secureBuilder() {
        try {
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
            factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
            factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
            factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
            factory.setXIncludeAware(false);
            factory.setExpandEntityReferences(false);
            factory.setNamespaceAware(false);
            DocumentBuilder builder = factory.newDocumentBuilder();
            // DefaultHandler : erreurs non fatales ignorées, erreur fatale levée (pas d'écriture sur la console).
            builder.setErrorHandler(new DefaultHandler());
            return builder;
        } catch (ParserConfigurationException e) {
            throw new IllegalStateException("Parseur XML indisponible", e);
        }
    }

    /** Remplace les ${propriété} connues ; une valeur restée non résolue est abandonnée (null). */
    static String resolve(String value, Map<String, String> own, Map<String, String> shared) {
        if (value == null) {
            return null;
        }
        String current = value.strip();
        for (int pass = 0; pass < 5 && current.contains("${"); pass++) {
            Matcher matcher = PROPERTY.matcher(current);
            StringBuilder resolved = new StringBuilder();
            while (matcher.find()) {
                String name = matcher.group(1);
                String replacement = own.getOrDefault(name, shared.get(name));
                matcher.appendReplacement(resolved, Matcher.quoteReplacement(replacement != null ? replacement : matcher.group()));
            }
            matcher.appendTail(resolved);
            current = resolved.toString();
        }
        return current.isEmpty() || current.contains("${") ? null : current;
    }

    /**
     * Ce qui sert dans un pom : propriétés, versions gérées (groupId:artifactId -> version), coordonnées des
     * BOM importés et du parent (pour la résolution transitive), dépendances déclarées.
     */
    private record Pom(Map<String, String> properties, Map<String, String> managed, List<String> managedImports,
                       String parent, List<Map<String, String>> dependencies) {

        static Pom parse(Document document) {
            Element project = document.getDocumentElement();
            Map<String, String> properties = new HashMap<>();
            Element parent = child(project, "parent");
            String version = text(project, "version");
            String groupId = text(project, "groupId");
            if (parent != null) {
                version = version != null ? version : text(parent, "version");
                groupId = groupId != null ? groupId : text(parent, "groupId");
                putIfPresent(properties, "project.parent.version", text(parent, "version"));
                putIfPresent(properties, "project.parent.groupId", text(parent, "groupId"));
            }
            putIfPresent(properties, "project.version", version);
            putIfPresent(properties, "version", version);
            putIfPresent(properties, "project.groupId", groupId);
            putIfPresent(properties, "project.artifactId", text(project, "artifactId"));
            Element props = child(project, "properties");
            if (props != null) {
                for (Element property : children(props)) {
                    putIfPresent(properties, property.getTagName(), property.getTextContent());
                }
            }
            Map<String, String> managed = new HashMap<>();
            List<String> imports = new ArrayList<>();
            Element management = child(project, "dependencyManagement");
            for (Map<String, String> dependency : dependencies(management == null ? null : child(management, "dependencies"))) {
                if (dependency.get("version") == null) {
                    continue;
                }
                if ("import".equals(dependency.get("scope"))) {
                    // BOM importé (spring-boot-dependencies...) : ses versions gérées sont lues à la demande.
                    imports.add(dependency.get("groupId") + ":" + dependency.get("artifactId") + ":"
                            + dependency.get("version"));
                } else {
                    managed.put(dependency.get("groupId") + ":" + dependency.get("artifactId"), dependency.get("version"));
                }
            }
            String parentCoordinates = parent == null ? null
                    : text(parent, "groupId") + ":" + text(parent, "artifactId") + ":" + text(parent, "version");
            return new Pom(properties, managed, imports, parentCoordinates, dependencies(child(project, "dependencies")));
        }

        private static List<Map<String, String>> dependencies(Element container) {
            List<Map<String, String>> result = new ArrayList<>();
            if (container == null) {
                return result;
            }
            for (Element dependency : children(container)) {
                if (!"dependency".equals(dependency.getTagName())) {
                    continue;
                }
                Map<String, String> fields = new HashMap<>();
                for (String field : List.of("groupId", "artifactId", "version", "scope", "optional")) {
                    putIfPresent(fields, field, text(dependency, field));
                }
                result.add(fields);
            }
            return result;
        }

        private static void putIfPresent(Map<String, String> map, String key, String value) {
            if (value != null && !value.isBlank()) {
                map.put(key, value.strip());
            }
        }

        private static List<Element> children(Element element) {
            List<Element> result = new ArrayList<>();
            for (Node node = element.getFirstChild(); node != null; node = node.getNextSibling()) {
                if (node instanceof Element child) {
                    result.add(child);
                }
            }
            return result;
        }

        private static Element child(Element element, String name) {
            return children(element).stream().filter(c -> name.equals(c.getTagName())).findFirst().orElse(null);
        }

        private static String text(Element element, String name) {
            Element child = child(element, name);
            return child == null ? null : child.getTextContent().strip();
        }
    }
}
