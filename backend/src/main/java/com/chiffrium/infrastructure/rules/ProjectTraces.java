package com.chiffrium.infrastructure.rules;

import com.chiffrium.application.port.ProjectScanner.ScannedFile;
import com.chiffrium.domain.model.Language;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.function.Predicate;

/**
 * Trace des valeurs pour les constats ({@code SecurityFindingDetector}) : un IV, un sel, un nombre d'itérations,
 * une graine ou un mot de passe passés par un paramètre, un champ ou une autre classe sont remontés jusqu'à
 * l'endroit où ils sont écrits, avec le même mécanisme que les algorithmes ({@link ValueTracer}). L'index du code
 * d'un langage n'est construit qu'à la première question qui le concerne.
 */
public final class ProjectTraces {

    /**
     * Valeur retrouvée.
     *
     * @param value     expression écrite dans le code (tableau d'octets, nombre, chaîne)
     * @param locations emplacements ("fichier:ligne") où elle est écrite
     * @param path      trajet jusqu'à l'appel, de l'endroit où elle est écrite au dernier relais
     */
    public record Origin(String value, List<String> locations, List<String> path) {
    }

    private final Path root;
    private final List<ScannedFile> files;
    private final List<RulePack> packs;
    private final Map<String, ProjectCode> codes = new HashMap<>();

    public ProjectTraces(Path root, List<ScannedFile> files, List<RulePack> packs) {
        this.root = root;
        this.files = List.copyOf(files);
        this.packs = List.copyOf(packs);
    }

    /**
     * @param terminal expression où s'arrêter (la valeur cherchée telle qu'elle s'écrit dans le code)
     * @return valeurs retrouvées, vide si le langage n'a pas de syntaxe connue ou si rien n'est retrouvé
     */
    public synchronized List<Origin> trace(String expression, String path, Language language, int line,
                                           Predicate<String> terminal) {
        Optional<RulePack> pack = packs.stream()
                .filter(p -> p.appliesTo(language) && !p.functionPatterns().isEmpty() && !p.rules().isEmpty())
                .findFirst();
        if (pack.isEmpty()) {
            return List.of();
        }
        ProjectCode code = codes.computeIfAbsent(pack.get().id(), id -> ProjectCode.load(root,
                files.stream().filter(f -> f.language() != null && pack.get().appliesTo(f.language())).toList(),
                l -> syntaxOf(l, pack.get())));
        ValueTracer tracer = new ValueTracer(code, new ConstantResolver(code::constants), terminal);
        List<Origin> origins = new ArrayList<>();
        for (ValueTracer.Traced traced : tracer.trace(expression, path, line)) {
            origins.add(new Origin(traced.value(), traced.origins(), traced.steps()));
        }
        return origins;
    }

    /** L'expression sans ses enveloppes neutres ({@code key.getBytes()}, {@code pwd.toCharArray()}...). */
    public static String unwrap(String expression) {
        return ValueTracer.unwrap(expression);
    }

    /** Syntaxe du langage : son paquet propre s'il en a un (VB.NET pour les règles C#), sinon celui des règles. */
    private RulePack syntaxOf(Language language, RulePack rules) {
        return packs.stream()
                .filter(p -> p.languages().equals(Set.of(language)) && !p.functionPatterns().isEmpty())
                .findFirst().orElse(rules);
    }
}
