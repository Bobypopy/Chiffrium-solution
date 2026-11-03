package com.chiffrium.infrastructure.rules;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Remonte la valeur d'un argument que {@link ConstantResolver} ne résout pas ({@code Cipher.getInstance(algo)},
 * {@code kpg.initialize(keySize)})
 * par les affectations du fichier (champ, variable) et par les appelants quand c'est un paramètre, sur quelques
 * sauts. Ce n'est pas une analyse de flux : une valeur calculée, choisie par une condition ou rangée dans une
 * collection n'est pas suivie, et un appel ambigu n'est pas relié ({@link ProjectCode}).
 *
 * <p>Chaque valeur trouvée garde son trajet, de l'endroit où elle est écrite jusqu'à l'appel qui l'utilise.
 * Plusieurs appelants peuvent donner plusieurs valeurs : chacune est un usage réel de l'API.
 */
final class ValueTracer {

    static final int MAX_HOPS = 4;
    static final int MAX_VALUES = 8;

    /** Taille de clé écrite en chiffres (même forme que {@code {SIZE}}). */
    private static final Pattern NUMBER = Pattern.compile("\\d{2,5}");
    private static final Pattern IDENTIFIER = Pattern.compile(
            "\\$?[A-Za-z_][\\w$]*(?:\\s*(?:\\.|->)\\s*\\$?[A-Za-z_][\\w$]*)*");
    /** Enveloppes qui ne changent pas le nom de l'algorithme. */
    private static final Pattern WRAPPER_CALL = Pattern.compile(
            "^(?:String\\s*\\.\\s*valueOf|new\\s+String|String|str)\\s*\\((?<inner>.*)\\)$", Pattern.DOTALL);
    private static final Pattern WRAPPER_METHOD = Pattern.compile(
            "^(?<inner>.+?)\\s*\\.\\s*(?:toCharArray|toString|trim|strip|toUpperCase|toLowerCase|upper|lower|intern)"
                    + "\\s*\\(\\s*\\)$", Pattern.DOTALL);

    /**
     * Valeur retrouvée.
     *
     * @param value  valeur littérale
     * @param steps  trajet, de l'endroit où la valeur est écrite jusqu'au dernier relais avant l'appel
     * @param origin emplacement où la valeur est écrite ("fichier:ligne")
     */
    record Traced(String value, List<String> steps, String origin) {
    }

    private record Hop(String path, int line) {
    }

    private final ProjectCode code;
    private final ConstantResolver resolver;

    ValueTracer(ProjectCode code, ConstantResolver resolver) {
        this.code = code;
        this.resolver = resolver;
    }

    /** Valeurs possibles de l'expression écrite à cette ligne ; vide si aucune n'est retrouvée. */
    List<Traced> trace(String expression, String path, int line) {
        Map<String, Traced> found = new LinkedHashMap<>();
        follow(expression, new Hop(path, line), 0, new ArrayList<>(), new HashSet<>(), found);
        return List.copyOf(found.values());
    }

    private void follow(String expression, Hop at, int hops, List<Hop> trail, Set<String> visited,
                        Map<String, Traced> found) {
        if (found.size() >= MAX_VALUES || expression == null) {
            return;
        }
        String unwrapped = unwrap(expression);
        Optional<SourceText> text = code.text(at.path());
        if (text.isEmpty()) {
            return;
        }
        if (NUMBER.matcher(unwrapped).matches()) {
            record(unwrapped, at, trail, found);
            return;
        }
        if (ConstantResolver.isLiteral(unwrapped) || unwrapped.contains("+")) {
            resolver.resolve(unwrapped, text.get().content()).ifPresent(value -> record(value, at, trail, found));
            return;
        }
        if (hops >= MAX_HOPS || !IDENTIFIER.matcher(unwrapped).matches()
                || !visited.add(at.path() + ":" + at.line() + ":" + unwrapped)) {
            return;
        }
        String name = ConstantResolver.lastSegment(unwrapped.replace("->", "."));
        int before = found.size();
        ProjectCode.FunctionDef function = code.functionAt(at.path(), at.line());
        int parameter = function == null || function.parameters() == null ? -1 : function.parameters().indexOf(name);

        List<ProjectCode.Assignment> assignments = code.assignments(at.path(), name).stream()
                .filter(a -> a.line() != at.line())
                .toList();
        List<ProjectCode.Assignment> local = function == null ? List.of() : assignments.stream()
                .filter(a -> a.line() > function.declaration().line() && a.line() < at.line())
                .toList();
        // Paramètre ou variable locale : seules comptent les affectations de la fonction ; sinon, un champ.
        for (ProjectCode.Assignment assignment : parameter >= 0 || !local.isEmpty() ? local : assignments) {
            Hop next = new Hop(at.path(), assignment.line());
            follow(assignment.expression(), next, hops + 1, with(trail, next), visited, found);
        }
        if (parameter >= 0) {
            for (ProjectCode.Call call : code.callersOf(function)) {
                if (parameter < call.arguments().size()) {
                    Hop next = new Hop(call.path(), call.line());
                    follow(call.arguments().get(parameter), next, hops + 1, with(trail, next), visited, found);
                }
            }
        }
        if (found.size() == before && hops > 0) {
            // Constante d'une autre classe (Config.ALGO) : connue de l'index du projet, sans emplacement précis.
            resolver.resolve(unwrapped, text.get().content()).ifPresent(value -> record(value, at, trail, found));
        }
    }

    private void record(String value, Hop origin, List<Hop> trail, Map<String, Traced> found) {
        List<String> steps = new ArrayList<>();
        for (int i = trail.size() - 1; i >= 0; i--) {
            steps.add(describe(trail.get(i)));
        }
        found.putIfAbsent(value, new Traced(value, List.copyOf(steps), origin.path() + ":" + origin.line()));
    }

    /** "Classe.méthode (chemin:ligne)", ou "chemin:ligne" hors de toute fonction. */
    private String describe(Hop hop) {
        ProjectCode.FunctionDef function = code.functionAt(hop.path(), hop.line());
        String location = hop.path() + ":" + hop.line();
        return function == null ? location : function.qualified() + " (" + location + ")";
    }

    private static List<Hop> with(List<Hop> trail, Hop hop) {
        List<Hop> extended = new ArrayList<>(trail);
        extended.add(hop);
        return extended;
    }

    static String unwrap(String expression) {
        String current = expression.trim();
        for (int i = 0; i < 5; i++) {
            String previous = current;
            if (current.startsWith("(") && current.endsWith(")")
                    && ProjectCode.arguments(current, 0) != null
                    && ProjectCode.arguments(current, 0).size() == 1
                    && current.length() == closing(current) + 1) {
                current = current.substring(1, current.length() - 1).trim();
            }
            Matcher call = WRAPPER_CALL.matcher(current);
            if (call.matches() && balanced(call.group("inner"))) {
                current = call.group("inner").trim();
            }
            Matcher method = WRAPPER_METHOD.matcher(current);
            if (method.matches()) {
                current = method.group("inner").trim();
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
