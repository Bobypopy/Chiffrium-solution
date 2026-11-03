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
            writeKnownDefaults(idsOf(defaults));
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
        if (added > 0) {
            save(new AlgorithmCatalog(current.schemaVersion(), algorithms, modes, paddings, curves));
            LOG.info("Catalogue mis à niveau : {} entrée(s) ajoutée(s) depuis le catalogue par défaut", added);
        }
        Set<String> updated = new HashSet<>(known);
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
