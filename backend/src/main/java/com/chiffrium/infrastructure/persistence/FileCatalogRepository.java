package com.chiffrium.infrastructure.persistence;

import com.chiffrium.application.port.CatalogRepository;
import com.chiffrium.domain.policy.AlgorithmCatalog;
import com.chiffrium.domain.policy.AlgorithmDefinition;
import com.chiffrium.domain.policy.ParameterDefinition;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;
import java.util.function.Function;

/**
 * Catalogue stocké dans un fichier JSON du volume de données. Au premier démarrage, il est initialisé
 * à partir du catalogue par défaut embarqué dans le JAR ; aux démarrages suivants, les entrées ajoutées au
 * catalogue par défaut par une nouvelle version y sont intégrées, sans modifier les entrées existantes ni
 * réintroduire celles que l'organisation a supprimées. Chaque sauvegarde conserve une copie de secours.
 */
public final class FileCatalogRepository implements CatalogRepository {

    private static final Logger LOG = LoggerFactory.getLogger(FileCatalogRepository.class);
    public static final String DEFAULT_CATALOG_RESOURCE = "/catalog/default-catalog.json";
    private static final String BACKUP_SUFFIX = ".bak";
    /** Identifiants des entrées par défaut déjà proposées (pour ne pas réintroduire une entrée supprimée). */
    private static final String KNOWN_DEFAULTS_SUFFIX = ".defaults.json";
    private static final String ALGORITHM = "algorithm:";
    private static final String MODE = "mode:";
    private static final String PADDING = "padding:";
    private static final String CURVE = "curve:";
    private static final String KEY_SIZES = "keysizes:";
    /**
     * Entrées par défaut existantes qui ont reçu des règles de taille dans une version ultérieure (niveaux CNSA
     * 2.0 de ML-KEM et ML-DSA) : ces règles sont reprises une seule fois, si l'organisation n'en a pas défini.
     */
    private static final Set<String> KEY_SIZE_RULES_ADDED = Set.of("ml-kem", "ml-dsa");
    /**
     * OID revus en 1.2.1 (un OID par jeu de paramètres, OID des courbes) : repris une seule fois par entrée, si
     * l'organisation n'y a pas ajouté les siens.
     */
    private static final String OID_REFS = "oids:";
    /** Racines de famille retirées du catalogue par défaut : elles ne désignent aucun algorithme précis. */
    private static final Set<String> RETIRED_OIDS = Set.of("2.16.840.1.101.3.4.1", "1.2.840.10045.4.3",
            "1.2.410.200046.1.1");

    private final Path file;
    private final ObjectMapper mapper;
    private AlgorithmCatalog cached;

    public FileCatalogRepository(Path file, ObjectMapper mapper) {
        this.file = file;
        this.mapper = mapper;
        initializeOrUpgrade();
    }

    /** Charge le catalogue par défaut embarqué (utile aussi pour les tests). */
    public static AlgorithmCatalog loadDefault(ObjectMapper mapper) {
        try (InputStream in = FileCatalogRepository.class.getResourceAsStream(DEFAULT_CATALOG_RESOURCE)) {
            if (in == null) {
                throw new IllegalStateException("Ressource manquante : " + DEFAULT_CATALOG_RESOURCE);
            }
            return validated(mapper.readValue(in, AlgorithmCatalog.class), DEFAULT_CATALOG_RESOURCE);
        } catch (IOException e) {
            throw new UncheckedIOException("Catalogue par défaut illisible", e);
        }
    }

    @Override
    public AlgorithmCatalog defaults() {
        return loadDefault(mapper);
    }

    @Override
    public synchronized AlgorithmCatalog load() {
        if (cached == null) {
            try {
                cached = validated(mapper.readValue(file.toFile(), AlgorithmCatalog.class), file.toString());
            } catch (IOException e) {
                throw new UncheckedIOException("Catalogue illisible : " + file, e);
            }
        }
        return cached;
    }

    @Override
    public synchronized void save(AlgorithmCatalog catalog) {
        validated(catalog, "catalogue modifié");
        try {
            if (Files.exists(file)) {
                Files.copy(file, file.resolveSibling(file.getFileName() + BACKUP_SUFFIX),
                        StandardCopyOption.REPLACE_EXISTING);
            }
        } catch (IOException e) {
            throw new UncheckedIOException("Sauvegarde de secours impossible : " + file, e);
        }
        AtomicFiles.writeJson(mapper, file, catalog);
        cached = catalog;
        LOG.info("Catalogue mis à jour ({} algorithmes)", catalog.algorithms().size());
    }

    private void initializeOrUpgrade() {
        AlgorithmCatalog defaults = loadDefault(mapper);
        if (!Files.exists(file)) {
            LOG.info("Initialisation du catalogue d'algorithmes dans {}", file);
            AtomicFiles.writeJson(mapper, file, defaults);
            writeKnownDefaults(withMigrations(idsOf(defaults), defaults));
            return;
        }
        AlgorithmCatalog current = load();
        // Avant la 2.3.2, rien n'était mémorisé : seules les entrées absentes du catalogue local sont nouvelles.
        Set<String> known = readKnownDefaults().orElseGet(() -> idsOf(current));
        Set<String> present = idsOf(current);
        List<AlgorithmDefinition> algorithms = new ArrayList<>(current.algorithms());
        List<ParameterDefinition> modes = new ArrayList<>(current.modes());
        List<ParameterDefinition> paddings = new ArrayList<>(current.paddings());
        List<ParameterDefinition> curves = new ArrayList<>(current.curves());
        int added = addNew(defaults.algorithms(), AlgorithmDefinition::id, ALGORITHM, present, known, algorithms)
                + addNew(defaults.modes(), ParameterDefinition::id, MODE, present, known, modes)
                + addNew(defaults.paddings(), ParameterDefinition::id, PADDING, present, known, paddings)
                + addNew(defaults.curves(), ParameterDefinition::id, CURVE, present, known, curves);
        int completed = completeKeySizeRules(defaults, known, algorithms)
                + refreshOids(defaults, known, algorithms, curves);
        if (added + completed > 0) {
            save(new AlgorithmCatalog(current.schemaVersion(), algorithms, modes, paddings, curves));
            LOG.info("Catalogue mis à niveau : {} entrée(s) ajoutée(s), {} complétée(s) depuis le catalogue par défaut",
                    added, completed);
        }
        Set<String> updated = withMigrations(new HashSet<>(known), defaults);
        updated.addAll(idsOf(defaults));
        if (!updated.equals(known)) {
            writeKnownDefaults(updated);
        }
    }

    private static <T> int addNew(List<T> defaults, Function<T, String> id, String prefix, Set<String> present,
                                  Set<String> known, List<T> target) {
        int added = 0;
        for (T entry : defaults) {
            String key = prefix + id.apply(entry);
            if (!present.contains(key) && !known.contains(key)) {
                target.add(entry);
                added++;
            }
        }
        return added;
    }

    /** Reprend une seule fois les règles de taille par défaut des entrées listées, sans écraser celles en place. */
    private static int completeKeySizeRules(AlgorithmCatalog defaults, Set<String> known,
                                            List<AlgorithmDefinition> algorithms) {
        int completed = 0;
        for (int i = 0; i < algorithms.size(); i++) {
            AlgorithmDefinition local = algorithms.get(i);
            if (!KEY_SIZE_RULES_ADDED.contains(local.id()) || known.contains(KEY_SIZES + local.id())
                    || !local.keySizeRules().isEmpty()) {
                continue;
            }
            Optional<AlgorithmDefinition> reference = defaults.findAlgorithm(local.id());
            if (reference.isPresent() && !reference.get().keySizeRules().isEmpty()) {
                algorithms.set(i, new AlgorithmDefinition(local.id(), local.name(), local.primitive(),
                        local.assetType(), local.aliases(), local.tokens(), local.oids(), local.status(),
                        local.quantumVulnerable(), reference.get().keySizeRules(), local.deprecatedAfter(),
                        local.disallowedAfter(), local.note(), local.recommendation(), local.references()));
                completed++;
            }
        }
        return completed;
    }

    /**
     * Reprend une seule fois les OID par défaut d'une entrée dont les OID locaux sont tous connus du catalogue par
     * défaut (ou retirés) : un OID ajouté par l'organisation empêche la reprise.
     */
    private static int refreshOids(AlgorithmCatalog defaults, Set<String> known, List<AlgorithmDefinition> algorithms,
                                   List<ParameterDefinition> curves) {
        int refreshed = 0;
        for (int i = 0; i < algorithms.size(); i++) {
            AlgorithmDefinition local = algorithms.get(i);
            Optional<AlgorithmDefinition> reference = defaults.findAlgorithm(local.id());
            if (reference.isPresent() && shouldRefresh(known, local.id(), local.oids(), reference.get().oids())) {
                algorithms.set(i, new AlgorithmDefinition(local.id(), local.name(), local.primitive(),
                        local.assetType(), local.aliases(), local.tokens(), reference.get().oids(), local.status(),
                        local.quantumVulnerable(), local.keySizeRules(), local.deprecatedAfter(),
                        local.disallowedAfter(), local.note(), local.recommendation(), local.references()));
                refreshed++;
            }
        }
        for (int i = 0; i < curves.size(); i++) {
            ParameterDefinition local = curves.get(i);
            Optional<ParameterDefinition> reference = defaults.curves().stream()
                    .filter(c -> c.id().equals(local.id())).findFirst();
            if (reference.isPresent() && shouldRefresh(known, CURVE + local.id(), local.oids(), reference.get().oids())) {
                curves.set(i, new ParameterDefinition(local.id(), local.name(), local.aliases(), local.tokens(),
                        local.status(), local.note(), reference.get().oids()));
                refreshed++;
            }
        }
        return refreshed;
    }

    private static boolean shouldRefresh(Set<String> known, String id, List<AlgorithmDefinition.OidRef> local,
                                         List<AlgorithmDefinition.OidRef> reference) {
        if (known.contains(OID_REFS + id) || local.equals(reference)) {
            return false;
        }
        Set<String> offered = new HashSet<>(RETIRED_OIDS);
        reference.forEach(ref -> offered.add(ref.oid()));
        return local.stream().allMatch(ref -> offered.contains(ref.oid()));
    }

    private static Set<String> withMigrations(Set<String> ids, AlgorithmCatalog defaults) {
        KEY_SIZE_RULES_ADDED.forEach(id -> ids.add(KEY_SIZES + id));
        defaults.algorithms().forEach(a -> ids.add(OID_REFS + a.id()));
        defaults.curves().forEach(c -> ids.add(OID_REFS + CURVE + c.id()));
        return ids;
    }

    private static Set<String> idsOf(AlgorithmCatalog catalog) {
        Set<String> ids = new HashSet<>();
        catalog.algorithms().forEach(a -> ids.add(ALGORITHM + a.id()));
        catalog.modes().forEach(m -> ids.add(MODE + m.id()));
        catalog.paddings().forEach(p -> ids.add(PADDING + p.id()));
        catalog.curves().forEach(c -> ids.add(CURVE + c.id()));
        return ids;
    }

    private Path knownDefaultsFile() {
        return file.resolveSibling(file.getFileName() + KNOWN_DEFAULTS_SUFFIX);
    }

    private Optional<Set<String>> readKnownDefaults() {
        Path known = knownDefaultsFile();
        if (!Files.exists(known)) {
            return Optional.empty();
        }
        try {
            return Optional.of(new HashSet<>(List.of(mapper.readValue(known.toFile(), String[].class))));
        } catch (IOException e) {
            LOG.warn("Liste des entrées par défaut illisible, reconstruite : {}", known, e);
            return Optional.empty();
        }
    }

    private void writeKnownDefaults(Set<String> ids) {
        AtomicFiles.writeJson(mapper, knownDefaultsFile(), new TreeSet<>(ids));
    }

    private static AlgorithmCatalog validated(AlgorithmCatalog catalog, String origin) {
        List<String> errors = catalog.validate();
        if (!errors.isEmpty()) {
            throw new IllegalStateException("Catalogue invalide (" + origin + ") : " + String.join(" ; ", errors));
        }
        return catalog;
    }
}
