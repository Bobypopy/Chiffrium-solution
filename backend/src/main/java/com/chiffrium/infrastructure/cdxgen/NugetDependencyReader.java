package com.chiffrium.infrastructure.cdxgen;

import com.chiffrium.infrastructure.cdxgen.DeclaredDependencies.Dependency;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import java.io.IOException;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * Dépendances .NET lues sans lancer {@code dotnet restore}.
 *
 * <p>Trois sources, de la plus précise à la moins précise :
 * <ul>
 *   <li>{@code packages.lock.json} : l'arbre résolu, transitives comprises, avec les versions exactes ;</li>
 *   <li>les fichiers projet ({@code .csproj}, {@code .vbproj}, {@code .fsproj}) et
 *       {@code Directory.Packages.props} : les dépendances directes, parfois sans version quand la gestion
 *       centralisée des versions est utilisée ;</li>
 *   <li>{@code packages.config} : les anciens projets, avant PackageReference.</li>
 * </ul>
 */
final class NugetDependencyReader {

    private static final Logger LOG = LoggerFactory.getLogger(NugetDependencyReader.class);
    private static final Pattern PROJECT_FILE = Pattern.compile(".+\\.(cs|vb|fs)proj$", Pattern.CASE_INSENSITIVE);
    private static final Pattern PROPS_FILE = Pattern.compile("directory\\.(packages|build)\\.props", Pattern.CASE_INSENSITIVE);
    /** Propriété MSBuild {@code $(Version)} : sans évaluation du projet, on ne sait pas la résoudre. */
    private static final Pattern MSBUILD_PROPERTY = Pattern.compile("\\$\\([^)]+\\)");

    private NugetDependencyReader() {
    }

    /** Dépendances NuGet du projet, dédoublonnées (clé : purl). */
    static Map<String, Dependency> read(Path projectRoot) throws IOException {
        Map<String, Dependency> result = new LinkedHashMap<>();
        for (Path file : DeclaredDependencies.files(projectRoot, "packages.lock.json"::equalsIgnoreCase)) {
            readLockFile(file, result);
        }
        // Versions centralisées (Directory.Packages.props) : servent de repli pour les projets qui n'en ont pas.
        Map<String, String> central = new HashMap<>();
        for (Path file : DeclaredDependencies.files(projectRoot, name -> PROPS_FILE.matcher(name).matches())) {
            readProjectFile(file, central, null);
        }
        for (Path file : DeclaredDependencies.files(projectRoot, name -> PROJECT_FILE.matcher(name).matches())) {
            readProjectFile(file, central, result);
        }
        for (Path file : DeclaredDependencies.files(projectRoot, "packages.config"::equalsIgnoreCase)) {
            readPackagesConfig(file, result);
        }
        return result;
    }

    /** Arbre résolu : {@code dependencies -> cadre cible -> paquet -> {type, resolved}}. */
    private static void readLockFile(Path file, Map<String, Dependency> into) {
        try {
            JsonNode root = new ObjectMapper().readTree(file.toFile());
            JsonNode frameworks = root.path("dependencies");
            for (Iterator<JsonNode> targets = frameworks.elements(); targets.hasNext(); ) {
                JsonNode packages = targets.next();
                for (Map.Entry<String, JsonNode> entry : packages.properties()) {
                    JsonNode details = entry.getValue();
                    // "Project" : un autre projet de la solution, pas un paquet publié.
                    if ("Project".equalsIgnoreCase(details.path("type").asText())) {
                        continue;
                    }
                    String version = text(details, "resolved", text(details, "requested", null));
                    add(into, entry.getKey(), version, false);
                }
            }
        } catch (IOException e) {
            LOG.debug("packages.lock.json illisible, ignoré : {}", file, e);
        }
    }

    /**
     * Fichier projet ou props MSBuild.
     *
     * @param central versions centralisées, alimentées par les {@code PackageVersion} et consultées ensuite
     * @param into    destination des dépendances, ou {@code null} pour ne collecter que les versions centrales
     */
    private static void readProjectFile(Path file, Map<String, String> central, Map<String, Dependency> into) {
        Document document;
        try {
            document = PomDependencyReader.secureBuilder().parse(file.toFile());
        } catch (Exception e) {
            LOG.debug("Projet .NET illisible, ignoré : {}", file, e);
            return;
        }
        for (Element element : elements(document)) {
            String tag = element.getTagName();
            boolean version = "PackageVersion".equalsIgnoreCase(tag);
            if (!version && !"PackageReference".equalsIgnoreCase(tag)) {
                continue;
            }
            String name = attribute(element, "Include", attribute(element, "Update", null));
            String value = attribute(element, "Version", childText(element, "Version"));
            if (name == null || name.isBlank()) {
                continue;
            }
            if (value != null && MSBUILD_PROPERTY.matcher(value).find()) {
                value = null; // "$(BouncyCastleVersion)" : non résoluble sans évaluer MSBuild.
            }
            if (version) {
                if (value != null) {
                    central.putIfAbsent(name, value);
                }
            } else if (into != null) {
                // Les paquets d'outillage de test ne sont pas livrés : même traitement que la portée test Maven.
                boolean optional = isTestOnly(name) || isTestOnly(file.getFileName().toString());
                add(into, name, value != null ? value : central.get(name), optional);
            }
        }
    }

    /** Ancien format : {@code <package id="X" version="Y" developmentDependency="true" />}. */
    private static void readPackagesConfig(Path file, Map<String, Dependency> into) {
        Document document;
        try {
            document = PomDependencyReader.secureBuilder().parse(file.toFile());
        } catch (Exception e) {
            LOG.debug("packages.config illisible, ignoré : {}", file, e);
            return;
        }
        for (Element element : elements(document)) {
            if (!"package".equalsIgnoreCase(element.getTagName())) {
                continue;
            }
            String name = attribute(element, "id", null);
            if (name != null && !name.isBlank()) {
                add(into, name, attribute(element, "version", null),
                        "true".equalsIgnoreCase(attribute(element, "developmentDependency", "false"))
                                || isTestOnly(name));
            }
        }
    }

    private static boolean isTestOnly(String name) {
        String lower = name.toLowerCase(java.util.Locale.ROOT);
        return lower.contains("test") || lower.startsWith("moq") || lower.startsWith("nunit")
                || lower.startsWith("xunit") || lower.startsWith("fluentassertions");
    }

    private static void add(Map<String, Dependency> into, String name, String version, boolean optional) {
        // Une plage NuGet ("[2.3.0,3.0)") n'est pas une version : mieux vaut ne rien affirmer.
        String exact = version == null || version.isBlank() || version.matches(".*[\\[\\](),*].*")
                ? null : version.strip();
        DeclaredDependencies.add(into, new Dependency("nuget", null, name.strip(), exact, optional));
    }

    private static java.util.List<Element> elements(Document document) {
        java.util.List<Element> result = new java.util.ArrayList<>();
        NodeList all = document.getElementsByTagName("*");
        for (int i = 0; i < all.getLength(); i++) {
            if (all.item(i) instanceof Element element) {
                result.add(element);
            }
        }
        return result;
    }

    private static String attribute(Element element, String name, String fallback) {
        for (int i = 0; i < element.getAttributes().getLength(); i++) {
            Node attribute = element.getAttributes().item(i);
            if (attribute.getNodeName().equalsIgnoreCase(name)) {
                return attribute.getNodeValue();
            }
        }
        return fallback;
    }

    private static String childText(Element element, String name) {
        for (Node node = element.getFirstChild(); node != null; node = node.getNextSibling()) {
            if (node instanceof Element child && child.getTagName().equalsIgnoreCase(name)) {
                return child.getTextContent().strip();
            }
        }
        return null;
    }

    private static String text(JsonNode node, String field, String fallback) {
        JsonNode value = node.path(field);
        return value.isTextual() && !value.asText().isBlank() ? value.asText() : fallback;
    }
}
