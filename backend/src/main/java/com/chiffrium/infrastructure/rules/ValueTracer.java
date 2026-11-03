package com.chiffrium.infrastructure.rules;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Remonte la valeur d'un argument que {@link ConstantResolver} ne résout pas ({@code Cipher.getInstance(algo)},
 * {@code kpg.initialize(keySize)}) sur quelques sauts :
 * <ul>
 *   <li>affectations du fichier (variable, champ, {@code this.algo = choisi}) ;</li>
 *   <li>appelants de la fonction quand c'est un paramètre, y compris {@code new}, {@code super(...)} et
 *       {@code this(...)}, et paramètres d'un constructeur d'en-tête ({@code record}, Kotlin, TypeScript) ;</li>
 *   <li>valeur renvoyée par un accesseur du projet ({@code getDescription()}) ;</li>
 *   <li>éléments d'une liste écrite dans le code et parcourue par une boucle.</li>
 * </ul>
 * Ce n'est pas une analyse de flux : une valeur calculée, lue dans une table d'association ou passée par
 * réflexion n'est pas suivie, et un appel ambigu n'est pas relié ({@link ProjectCode}).
 *
 * <p>Chaque valeur garde ses trajets, de l'endroit où elle est écrite jusqu'à l'appel qui l'utilise : plusieurs
 * appelants qui transmettent la même valeur donnent plusieurs trajets, des valeurs différentes plusieurs
 * valeurs (chacune est un usage réel de l'API).
 */
final class ValueTracer {

    /** java-jwt : appelant, accesseur, champ, super(...), this(...) deux fois, new : sept sauts. */
    static final int MAX_HOPS = 8;
    static final int MAX_VALUES = 8;
    static final int MAX_PATHS = 10;

    /** Taille de clé écrite en chiffres (même forme que {@code {SIZE}}). */
    private static final Pattern NUMBER = Pattern.compile("\\d{2,5}");
    private static final Pattern IDENTIFIER = Pattern.compile(
            "\\$?[A-Za-z_][\\w$]*(?:\\s*(?:\\.|->)\\s*\\$?[A-Za-z_][\\w$]*)*");
    /** Appel sans argument : accesseur du projet, ou accesseur implicite (record, propriété). */
    private static final Pattern GETTER = Pattern.compile(
            "^(?:(?<receiver>this|self|[\\w$]+)\\s*\\.\\s*)?(?<name>[A-Za-z_$][\\w$]*)\\s*\\(\\s*\\)$");
    /** Enveloppes qui ne changent pas le nom de l'algorithme. */
    private static final Pattern WRAPPER_CALL = Pattern.compile(
            "^(?:String\\s*\\.\\s*valueOf|new\\s+String|String|str)\\s*\\((?<inner>.*)\\)$", Pattern.DOTALL);
    private static final Pattern WRAPPER_METHOD = Pattern.compile(
            "^(?<inner>.+?)\\s*\\.\\s*(?:toCharArray|toString|trim|strip|toUpperCase|toLowerCase|upper|lower|intern)"
                    + "\\s*\\(\\s*\\)$", Pattern.DOTALL);
    /** Élément d'un tableau ou d'une liste : toutes les valeurs de la collection sont possibles. */
    private static final Pattern INDEXED = Pattern.compile("^(?<inner>[\\w$.]+)\\s*\\[[^\\]]*\\]$");
    /** Liste écrite dans le code : ses éléments sont les valeurs possibles. */
    private static final Pattern COLLECTION = Pattern.compile(
            "^(?:[\\w.]+\\.)?(?:(?:List|Set|Stream)\\s*\\.\\s*of|Arrays\\s*\\.\\s*asList|listOf|setOf|arrayOf|mutableListOf"
                    + "|mutableSetOf|frozenset|tuple)\\s*\\((?<items>.*)\\)$"
                    + "|^(?:new\\s+[\\w.]+\\s*\\[\\s*\\]\\s*)?\\{(?<braces>.*)\\}$"
                    + "|^\\[(?<brackets>.*)\\]$", Pattern.DOTALL);

    /**
     * Valeur retrouvée.
     *
     * @param value   valeur littérale
     * @param paths   trajets (au plus {@link #MAX_PATHS}), chacun de l'endroit où la valeur est écrite jusqu'au
     *                dernier relais avant l'appel
     * @param origins emplacements ("fichier:ligne") où la valeur est écrite telle quelle
     */
    record Traced(String value, List<List<String>> paths, List<String> origins) {

        List<String> steps() {
            return paths.isEmpty() ? List.of() : paths.get(0);
        }
    }

    private record Hop(String path, int line) {
    }

    private static final class Found {
        private final Set<List<String>> paths = new LinkedHashSet<>();
        private final Set<String> origins = new LinkedHashSet<>();
    }

    private final ProjectCode code;
    private final ConstantResolver resolver;

    ValueTracer(ProjectCode code, ConstantResolver resolver) {
        this.code = code;
        this.resolver = resolver;
    }

    /** Valeurs possibles de l'expression écrite à cette ligne ; vide si aucune n'est retrouvée. */
    List<Traced> trace(String expression, String path, int line) {
        Map<String, Found> found = new LinkedHashMap<>();
        follow(expression, new Hop(path, line), 0, null, new ArrayList<>(), new HashSet<>(), found);
        List<Traced> traced = new ArrayList<>();
        found.forEach((value, f) -> traced.add(new Traced(value, List.copyOf(f.paths), List.copyOf(f.origins))));
        return traced;
    }

    /**
     * @param self classe de {@code this} quand la valeur vient d'un accesseur appelé sur l'objet courant : seuls
     *             comptent alors les {@code super(...)} de cette classe, pas ceux des autres sous-classes
     */
    private void follow(String expression, Hop at, int hops, String self, List<Hop> trail, Set<String> visited,
                        Map<String, Found> found) {
        if (expression == null) {
            return;
        }
        String unwrapped = unwrap(expression);
        Optional<SourceText> text = code.text(at.path());
        if (text.isEmpty()) {
            return;
        }
        if (NUMBER.matcher(unwrapped).matches()) {
            record(unwrapped, at, trail, found, true);
            return;
        }
        if (ConstantResolver.isLiteral(unwrapped) || unwrapped.contains("+")) {
            resolver.resolve(unwrapped, text.get().content())
                    .ifPresent(value -> record(value, at, trail, found, ConstantResolver.isLiteral(unwrapped)));
            return;
        }
        if (hops >= MAX_HOPS || !visited.add(at.path() + ":" + at.line() + ":" + unwrapped + ":" + self)) {
            return;
        }
        Matcher collection = COLLECTION.matcher(unwrapped);
        if (collection.matches()) {
            String items = firstNonNull(collection.group("items"), collection.group("braces"),
                    collection.group("brackets"));
            List<String> elements = ProjectCode.arguments("(" + items + ")", 0);
            if (elements != null) {
                elements.forEach(e -> follow(e, at, hops + 1, self, trail, visited, found));
            }
            return;
        }
        Matcher getter = GETTER.matcher(unwrapped);
        if (getter.matches()) {
            String receiver = getter.group("receiver");
            ProjectCode.FunctionDef current = code.functionAt(at.path(), at.line());
            String getterSelf = (receiver == null || receiver.equals("this") || receiver.equals("self"))
                    && current != null ? current.declaration().container() : self;
            followGetter(getter.group("name"), at, hops, getterSelf, trail, visited, found);
            return;
        }
        if (IDENTIFIER.matcher(unwrapped).matches()) {
            followName(unwrapped, text.get(), at, hops, self, trail, visited, found);
        }
    }

    /** Valeur renvoyée par l'accesseur ; à défaut (accesseur implicite d'un record, propriété), le champ. */
    private void followGetter(String name, Hop at, int hops, String self, List<Hop> trail, Set<String> visited,
                              Map<String, Found> found) {
        Optional<ProjectCode.Call> call = code.callAt(at.path(), at.line(), name);
        if (call.isEmpty()) {
            follow(name, at, hops, self, trail, visited, found);
            return;
        }
        ProjectCode.FunctionDef getter = call.get().callee();
        for (ProjectCode.Assignment returned : code.returns(getter)) {
            Hop next = new Hop(getter.path(), returned.line());
            follow(returned.expression(), next, hops + 1, self, with(trail, next), visited, found);
        }
    }

    private void followName(String expression, SourceText text, Hop at, int hops, String self, List<Hop> trail,
                            Set<String> visited, Map<String, Found> found) {
        String name = ConstantResolver.lastSegment(expression.replace("->", "."));
        int before = pathCount(found);
        ProjectCode.FunctionDef function = code.functionAt(at.path(), at.line());
        int parameter = function == null || function.parameters() == null ? -1 : function.parameters().indexOf(name);
        int start = function == null ? 0 : function.declaration().line();

        List<ProjectCode.Assignment> assignments = code.assignments(at.path(), name).stream()
                .filter(a -> a.line() != at.line())
                .toList();
        List<ProjectCode.Assignment> local = function == null ? List.of() : assignments.stream()
                .filter(a -> a.line() > start && a.line() < at.line())
                .toList();
        List<ProjectCode.Assignment> loops = function == null ? List.of() : code.loops(at.path(), name).stream()
                .filter(a -> a.line() >= start && a.line() <= at.line())
                .toList();
        // Paramètre, variable locale ou variable de boucle : seules comptent les valeurs données dans la
        // fonction ; sinon, c'est un champ, affecté n'importe où dans le fichier.
        boolean localName = parameter >= 0 || !local.isEmpty() || !loops.isEmpty();
        List<ProjectCode.Assignment> sources = localName ? local : assignments;
        for (ProjectCode.Assignment assignment : sources) {
            Hop next = new Hop(at.path(), assignment.line());
            follow(assignment.expression(), next, hops + 1, self, with(trail, next), visited, found);
        }
        for (ProjectCode.Assignment loop : loops) {
            Hop next = new Hop(at.path(), loop.line());
            follow(loop.expression(), next, hops + 1, self, with(trail, next), visited, found);
        }
        if (parameter >= 0) {
            followCallers(function, parameter, hops, self, trail, visited, found);
        } else if (!localName && sources.isEmpty() && function != null) {
            // Champ sans affectation : paramètre d'un constructeur d'en-tête (record, Kotlin, TypeScript).
            ProjectCode.FunctionDef constructor = code.constructorWithParameter(at.path(),
                    function.declaration().container(), name);
            if (constructor != null && !constructor.equals(function)) {
                followCallers(constructor, constructor.parameters().indexOf(name), hops, self, trail, visited,
                        found);
            }
        }
        if (pathCount(found) == before && hops > 0) {
            // Constante d'une autre classe (Config.ALGO) : connue de l'index du projet, sans emplacement précis.
            resolver.resolve(expression, text.content()).ifPresent(value -> record(value, at, trail, found, false));
        }
    }

    private void followCallers(ProjectCode.FunctionDef function, int parameter, int hops, String self,
                               List<Hop> trail, Set<String> visited, Map<String, Found> found) {
        List<ProjectCode.Call> calls = code.callersOf(function);
        if (self != null && function.isConstructor() && !function.declaration().container().equals(self)) {
            // Constructeur d'une classe parente atteint depuis this : seuls les super(...) de la classe de this ;
            // aucun s'ils n'ont pas été retrouvés, plutôt que les valeurs des autres sous-classes.
            calls = calls.stream().filter(c -> self.equals(containerOf(c.caller()))).toList();
        }
        for (ProjectCode.Call call : calls) {
            if (parameter < call.arguments().size()) {
                Hop next = new Hop(call.path(), call.line());
                follow(call.arguments().get(parameter), next, hops + 1, null, with(trail, next), visited, found);
            }
        }
    }

    /**
     * @param literal vrai si la valeur est écrite telle quelle à cet endroit (il devient un emplacement de
     *                l'actif) ; faux pour une constante retrouvée par l'index du projet
     */
    private void record(String value, Hop at, List<Hop> trail, Map<String, Found> found, boolean literal) {
        Found entry = found.get(value);
        if (entry == null) {
            if (found.size() >= MAX_VALUES) {
                return;
            }
            entry = new Found();
            found.put(value, entry);
        }
        if (entry.paths.size() < MAX_PATHS) {
            List<String> steps = new ArrayList<>();
            for (int i = trail.size() - 1; i >= 0; i--) {
                steps.add(describe(trail.get(i)));
            }
            entry.paths.add(List.copyOf(steps));
        }
        if (literal) {
            entry.origins.add(at.path() + ":" + at.line());
        }
    }

    /** "Classe.méthode (chemin:ligne)", ou "chemin:ligne" hors de toute fonction. */
    private String describe(Hop hop) {
        ProjectCode.FunctionDef function = code.functionAt(hop.path(), hop.line());
        String location = hop.path() + ":" + hop.line();
        return function == null ? location : function.qualified() + " (" + location + ")";
    }

    /** Trajets déjà retrouvés, toutes valeurs confondues : une même valeur peut arriver par un nouveau trajet. */
    private static int pathCount(Map<String, Found> found) {
        return found.values().stream().mapToInt(f -> f.paths.size()).sum();
    }

    /** "Classe.méthode" -> "Classe". */
    private static String containerOf(String qualified) {
        return qualified == null || qualified.lastIndexOf('.') < 0 ? null
                : qualified.substring(0, qualified.lastIndexOf('.'));
    }

    private static List<Hop> with(List<Hop> trail, Hop hop) {
        List<Hop> extended = new ArrayList<>(trail);
        extended.add(hop);
        return extended;
    }

    private static String firstNonNull(String... values) {
        for (String value : values) {
            if (value != null) {
                return value;
            }
        }
        return "";
    }

    static String unwrap(String expression) {
        String current = expression.trim();
        for (int i = 0; i < 5; i++) {
            String previous = current;
            if (current.startsWith("(") && current.endsWith(")") && closing(current) == current.length() - 1) {
                List<String> inner = ProjectCode.arguments(current, 0);
                if (inner != null && inner.size() == 1) {
                    current = inner.get(0);
                }
            }
            Matcher call = WRAPPER_CALL.matcher(current);
            if (call.matches() && balanced(call.group("inner"))) {
                current = call.group("inner").trim();
            }
            Matcher method = WRAPPER_METHOD.matcher(current);
            if (method.matches()) {
                current = method.group("inner").trim();
            }
            Matcher indexed = INDEXED.matcher(current);
            if (indexed.matches()) {
                current = indexed.group("inner");
            }
            if (current.endsWith("!!")) {
                current = current.substring(0, current.length() - 2).trim();
            }
            if (current.equals(previous)) {
                break;
            }
        }
        return current;
    }

    private static int closing(String text) {
        int depth = 0;
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            if (c == '(') {
                depth++;
            } else if (c == ')' && --depth == 0) {
                return i;
            }
        }
        return -1;
    }

    private static boolean balanced(String text) {
        int depth = 0;
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            if (c == '(') {
                depth++;
            } else if (c == ')' && --depth < 0) {
                return false;
            }
        }
        return depth == 0;
    }
}
