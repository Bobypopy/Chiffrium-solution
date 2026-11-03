package com.chiffrium.infrastructure.cdxgen;

import com.chiffrium.application.port.SbomGenerator;
import com.chiffrium.domain.model.Language;
import com.chiffrium.infrastructure.process.ProcessRunner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.EnumMap;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

/**
 * Pilote cdxgen. Points importants (voir docs/cdxgen.md) :
 * <ul>
 *   <li>cdxgen ne produit les slices d'évidence que pour le <b>premier</b> type passé avec -t :
 *       on lance donc une exécution par écosystème ;</li>
 *   <li>la cryptographie n'est taggée par atom que pour Java et Python : --include-crypto n'est passé
 *       que pour ces langages (configurable), les autres produisent un SBOM simple ;</li>
 *   <li>les chemins des slices sont imposés via --usages-slices-file / --reachables-slices-file, car le
 *       calcul par défaut de cdxgen dépend du répertoire courant ;</li>
 *   <li>--no-install-deps par défaut : l'installation des dépendances exécuterait des scripts du dépôt analysé.
 *       Cette option n'empêche pas cdxgen de lancer Maven, Gradle, sbt ou Mill (d'abord le wrapper du dépôt :
 *       mvnw, gradlew), ni pipenv, poetry, swift ou rush, qui exécutent aussi du code du dépôt. Dans ce mode, une
 *       liste blanche (CDXGEN_ALLOWED_COMMANDS) ne laisse lancer que atom, go et jar, et les dépendances
 *       Maven/Gradle sont lues sans outil de build par {@link DeclaredDependencies}.</li>
 * </ul>
 */
public final class CdxgenSbomGenerator implements SbomGenerator {

    private static final Logger LOG = LoggerFactory.getLogger(CdxgenSbomGenerator.class);
    private static final String SPEC_VERSION = "1.6";
    private static final Duration VERSION_TIMEOUT = Duration.ofSeconds(60);
    private static final Pattern VERSION_PATTERN = Pattern.compile("(\\d+\\.\\d+\\.\\d+)");
    private static final String UNAVAILABLE = "indisponible";
    private static final String TEMP_DIR_NAME = "cdxgen-tmp";
    private static final String ATOM_EXTENSION = ".atom";
    /** Outils dont la simple lecture des dépendances exécute du code du dépôt analysé (wrapper, scripts de build). */
    private static final List<String> BUILD_SCRIPT_TOOLS = List.of("maven", "gradle", "sbt", "mill");
    private static final String DECLARED_BOM = "bom-declared.json";
    /**
     * Seuls programmes que cdxgen peut lancer quand les outils de build sont désactivés : atom (lanceur "atom"
     * de l'application de bureau, ou "node" dans l'image cdxgen), go et jar, qui lisent sans exécuter le
     * dépôt. Tout le reste (mvnw, gradlew, pipenv, poetry, swift, rush, git...) est refusé par cdxgen.
     */
    private static final List<String> ALLOWED_COMMANDS = List.of("atom", "node", "go", "jar");

    /** Type de projet cdxgen pour chaque langage (plusieurs langages peuvent partager un type). */
    private static final Map<Language, String> CDXGEN_TYPES = new EnumMap<>(Map.ofEntries(
            Map.entry(Language.JAVA, "java"), Map.entry(Language.KOTLIN, "java"), Map.entry(Language.GROOVY, "java"),
            Map.entry(Language.SCALA, "scala"), Map.entry(Language.PYTHON, "python"),
            Map.entry(Language.JAVASCRIPT, "js"), Map.entry(Language.TYPESCRIPT, "js"),
            Map.entry(Language.GO, "go"), Map.entry(Language.CSHARP, "dotnet"),
            Map.entry(Language.C, "c"), Map.entry(Language.CPP, "c"),
            Map.entry(Language.PHP, "php"), Map.entry(Language.RUBY, "ruby"),
            Map.entry(Language.RUST, "rust"), Map.entry(Language.SWIFT, "swift"),
            Map.entry(Language.DART, "dart"), Map.entry(Language.ELIXIR, "elixir")));

    private final String command;
    private final Set<Language> cryptoLanguages;
    private final boolean installDeps;
    private final ProcessRunner processRunner;
    private volatile String cachedVersion;

    public CdxgenSbomGenerator(String command, Set<Language> cryptoLanguages, boolean installDeps,
                               ProcessRunner processRunner) {
        this.command = command;
        this.cryptoLanguages = cryptoLanguages.isEmpty() ? Set.of() : EnumSet.copyOf(cryptoLanguages);
        this.installDeps = installDeps;
        this.processRunner = processRunner;
    }

    @Override
    public SbomResult generate(Path projectRoot, Set<Language> languages, Path outputDir, Duration timeout) {
        List<Path> boms = new ArrayList<>();
        Map<Language, Path> usages = new EnumMap<>(Language.class);
        Map<Language, Path> reachables = new EnumMap<>(Language.class);
        List<String> warnings = new ArrayList<>();
        Path cdxgenTemp = createPrivateTempDir(outputDir);
        Map<String, String> environment = new HashMap<>(Map.of(
                "FETCH_LICENSE", "false",
                // cdxgen (evinser.js) supprime récursivement le dossier des slices s'il est sous son répertoire
                // temporaire : on lui en impose un dédié, frère (et non parent) du dossier de sortie.
                "CDXGEN_TEMP_DIR", cdxgenTemp.toString()));
        if (!installDeps) {
            environment.put("CDXGEN_ALLOWED_COMMANDS", allowedCommands(System.getenv("ATOM_CMD")));
        }

        for (Map.Entry<String, Language> entry : typesFor(languages).entrySet()) {
            String type = entry.getKey();
            Language language = entry.getValue();
            boolean withCrypto = cryptoLanguages.stream().anyMatch(l -> type.equals(CDXGEN_TYPES.get(l)));
            Invocation invocation = new Invocation(type, outputDir, withCrypto);
            try {
                ProcessRunner.Result result = processRunner.run(invocation.command(command, installDeps, projectRoot),
                        outputDir, environment, timeout, "cdxgen " + type);
                if (!result.succeeded()) {
                    warnings.add("cdxgen (" + type + ") " + (result.timedOut()
                            ? "a dépassé le délai de " + timeout.toSeconds() + " s"
                            : "a échoué (code " + result.exitCode() + ")"));
                }
            } catch (IOException e) {
                warnings.add("cdxgen introuvable ou non exécutable (" + command + ") : " + e.getMessage());
                LOG.error("Impossible de lancer cdxgen", e);
                break;
            }
            if (nonEmpty(invocation.bom())) {
                boms.add(invocation.bom());
            } else {
                warnings.add("cdxgen (" + type + ") n'a pas produit de BOM.");
            }
            if (withCrypto) {
                if (nonEmpty(invocation.usages())) {
                    usages.put(language, invocation.usages());
                }
                if (nonEmpty(invocation.reachables())) {
                    reachables.put(language, invocation.reachables());
                } else {
                    warnings.add("cdxgen (" + type + ") : pas de slice d'accessibilité, analyse de flux crypto indisponible.");
                }
            }
        }
        if (!installDeps && typesFor(languages).containsKey("java")) {
            try {
                DeclaredDependencies.writeBom(DeclaredDependencies.read(projectRoot), outputDir.resolve(DECLARED_BOM))
                        .ifPresent(boms::add);
            } catch (IOException | RuntimeException e) {
                warnings.add("Lecture des dépendances Maven/Gradle impossible : " + e.getMessage());
                LOG.warn("Lecture des dépendances Maven/Gradle impossible dans {}", projectRoot, e);
            }
        }
        try {
            warnings.addAll(ComputedDependencies.warnings(projectRoot));
        } catch (IOException | RuntimeException e) {
            LOG.debug("Recherche des dépendances calculées impossible dans {}", projectRoot, e);
        }
        deleteQuietly(cdxgenTemp);
        deleteAtomFiles(outputDir);
        return new SbomResult(boms, usages, reachables, warnings);
    }

    /** Liste blanche de cdxgen ; un ATOM_CMD personnalisé (premier mot, comme le découpe cdxgen) y est ajouté. */
    static String allowedCommands(String atomCommand) {
        List<String> commands = new ArrayList<>(ALLOWED_COMMANDS);
        if (atomCommand != null && !atomCommand.isBlank()) {
            String first = atomCommand.strip().split(" ")[0];
            if (!commands.contains(first)) {
                commands.add(first);
            }
        }
        return String.join(",", commands);
    }

    private static Path createPrivateTempDir(Path outputDir) {
        Path temp = outputDir.toAbsolutePath().resolveSibling(TEMP_DIR_NAME);
        try {
            Files.createDirectories(temp);
        } catch (IOException e) {
            throw new UncheckedIOException("Impossible de créer " + temp, e);
        }
        return temp;
    }

    /** Les bases atom intermédiaires (souvent volumineuses) ne servent plus une fois les slices produites. */
    private static void deleteAtomFiles(Path outputDir) {
        try (Stream<Path> files = Files.list(outputDir)) {
            files.filter(f -> f.getFileName().toString().endsWith(ATOM_EXTENSION)).forEach(f -> f.toFile().delete());
        } catch (IOException e) {
            LOG.debug("Nettoyage des fichiers atom impossible dans {}", outputDir, e);
        }
    }

    private static void deleteQuietly(Path dir) {
        try (Stream<Path> paths = Files.walk(dir)) {
            paths.sorted(Comparator.reverseOrder()).forEach(path -> path.toFile().delete());
        } catch (IOException e) {
            LOG.debug("Nettoyage incomplet de {}", dir, e);
        }
    }

    @Override
    public String version() {
        String version = cachedVersion;
        if (version == null) {
            version = detectVersion();
            cachedVersion = version;
        }
        return version;
    }

    private String detectVersion() {
        try {
            ProcessRunner.Result result = processRunner.run(List.of(command, "--version"), Path.of("."), Map.of(),
                    VERSION_TIMEOUT, "cdxgen --version");
            for (String line : result.lastOutput()) {
                Matcher matcher = VERSION_PATTERN.matcher(line);
                if (line.contains("CycloneDX Generator") && matcher.find()) {
                    return matcher.group(1);
                }
            }
        } catch (IOException e) {
            LOG.warn("cdxgen introuvable ({}) : seul le moteur de règles sera disponible", command);
        }
        return UNAVAILABLE;
    }

    /** Un seul lancement par type cdxgen ; le langage conservé sert de clé pour les slices. */
    static Map<String, Language> typesFor(Set<Language> languages) {
        Map<String, Language> types = new LinkedHashMap<>();
        languages.stream()
                .filter(CDXGEN_TYPES::containsKey)
                .sorted()
                .forEach(l -> types.putIfAbsent(CDXGEN_TYPES.get(l), l));
        return types;
    }

    private static boolean nonEmpty(Path file) {
        try {
            return Files.isRegularFile(file) && Files.size(file) > 0;
        } catch (IOException e) {
            return false;
        }
    }

    /**
     * Chemins de sortie et ligne de commande d'une exécution.
     */
    record Invocation(String type, Path outputDir, boolean withCrypto) {

        Path bom() {
            return outputDir.resolve("bom-" + type + ".json");
        }

        Path usages() {
            return outputDir.resolve(type + "-usages.slices.json");
        }

        Path reachables() {
            return outputDir.resolve(type + "-reachables.slices.json");
        }

        List<String> command(String executable, boolean installDeps, Path projectRoot) {
            List<String> cmd = new ArrayList<>(List.of(executable, "-t", type, "--spec-version", SPEC_VERSION,
                    "--json-pretty", "-o", bom().toString()));
            if (!installDeps) {
                cmd.add("--no-install-deps");
                BUILD_SCRIPT_TOOLS.forEach(tool -> cmd.addAll(List.of("--exclude-type", tool)));
            }
            if (withCrypto) {
                cmd.addAll(List.of("--include-crypto", "--deep",
                        "--usages-slices-file", usages().toString(),
                        "--reachables-slices-file", reachables().toString()));
            }
            cmd.add(projectRoot.toString());
            return cmd;
        }
    }
}
