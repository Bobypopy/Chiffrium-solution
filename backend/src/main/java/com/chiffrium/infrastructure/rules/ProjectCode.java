package com.chiffrium.infrastructure.rules;

import com.chiffrium.application.port.CallEdgeExtractor.CallEdge;
import com.chiffrium.application.port.ProjectScanner.ScannedFile;
import com.chiffrium.domain.model.Language;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.function.Function;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Code d'un paquet de règles à l'échelle du projet : fonctions déclarées, appels entre elles et affectations.
 * Sert au graphe quand cdxgen ne fournit pas les appels (langages autres que Java et Python, ligne de commande)
 * et à la trace des valeurs transmises d'une fonction à l'autre ({@link ValueTracer}).
 *
 * <p>Un appel est relié à sa déclaration par le nom, le receveur ({@code bc.go()} avec {@code Classe bc},
 * {@code Classe.go()}, {@code this.go()}, {@code new Classe()}) et le nombre d'arguments. Un appel ambigu
 * (homonymes indiscernables) n'est pas relié : mieux vaut un lien absent qu'un lien faux.
 */
final class ProjectCode {

    private static final Logger LOG = LoggerFactory.getLogger(ProjectCode.class);

    private static final Pattern CALL = Pattern.compile("(?<![\\w$])(?<name>[A-Za-z_$][\\w$]*)\\s*\\(");
    private static final Pattern IDENTIFIER = Pattern.compile("[A-Za-z_$][\\w$]*");
    private static final Pattern ANNOTATION = Pattern.compile("@[\\w.]+(?:\\([^)]*\\))?\\s*");
    private static final Set<String> SELF = Set.of("this", "self");
    /** Premier paramètre implicite d'une méthode Python : absent des arguments de l'appel. */
    private static final Set<String> IMPLICIT_PARAMETERS = Set.of("self", "cls");
    private static final String NEW = "new";
    private static final String CHAINED = "()";
    private static final int TEXT_CACHE_SIZE = 32;

    /**
     * Fonction déclarée.
     *
     * @param parameters noms des paramètres, null si la signature n'a pas pu être lue
     * @param required   nombre de paramètres sans valeur par défaut
     */
    record FunctionDef(String path, ScopeResolver.Declaration declaration, List<String> parameters, int required) {

        String qualified() {
            return declaration.qualified();
        }

        boolean accepts(int arguments) {
            return parameters == null || (arguments >= required && arguments <= parameters.size());
        }
    }

    /**
     * Appel d'une fonction du projet.
     *
     * @param caller    fonction appelante ("Classe.méthode"), null au niveau du module
     * @param arguments expressions passées, dans l'ordre
     */
    record Call(String path, int line, String caller, FunctionDef callee, List<String> arguments) {
    }

    /** Affectation {@code nom = expression} : expression et ligne. */
    record Assignment(String expression, int line) {
    }

    private record Loaded(SourceText text, ScopeResolver scopes, String stem, Set<Integer> commentLines) {
    }

    private final Path root;
    private final Map<String, ScannedFile> files = new LinkedHashMap<>();
    private final Function<Language, RulePack> scopePack;
    private final List<String> commentPrefixes;
    private final Map<String, List<String>> constants = new HashMap<>();
    private final Map<String, List<FunctionDef>> functionsByName = new HashMap<>();
    private final Map<String, FunctionDef> functionsByLocation = new HashMap<>();
    private final List<Call> calls = new ArrayList<>();
    private final Map<FunctionDef, List<Call>> callers = new HashMap<>();
    private final Map<String, Loaded> cache = new LinkedHashMap<>(16, 0.75f, true) {
        @Override
        protected boolean removeEldestEntry(Map.Entry<String, Loaded> eldest) {
            return size() > TEXT_CACHE_SIZE;
        }
    };

    private ProjectCode(Path root, List<ScannedFile> files, Function<Language, RulePack> scopePack,
                        List<String> commentPrefixes) {
        this.root = root;
        files.forEach(f -> this.files.put(f.path(), f));
        this.scopePack = scopePack;
        this.commentPrefixes = commentPrefixes;
    }

    /**
     * Lit les fichiers deux fois : déclarations et constantes d'abord, puis les appels, que l'on ne peut relier
     * qu'une fois toutes les déclarations connues. Seul l'index est gardé en mémoire, pas le texte.
     */
    static ProjectCode load(Path root, List<ScannedFile> files, Function<Language, RulePack> scopePack,
                            List<String> commentPrefixes) {
        ProjectCode code = new ProjectCode(root, files, scopePack, commentPrefixes);
        code.indexDeclarations();
        code.indexCalls();
        return code;
    }

    Map<String, List<String>> constants() {
        return constants;
    }

    /** Appels entre fonctions du projet, pour le graphe (un lien par paire appelant-appelé). */
    List<CallEdge> callEdges() {
        Map<String, CallEdge> edges = new LinkedHashMap<>();
        for (Call call : calls) {
            if (call.caller() != null && !call.caller().equals(call.callee().qualified())) {
                edges.putIfAbsent(call.caller() + "->" + call.callee().qualified(),
                        new CallEdge(call.caller(), call.callee().qualified(), call.path(), call.line(), false));
            }
        }
        return List.copyOf(edges.values());
    }

    List<Call> callersOf(FunctionDef function) {
        return callers.getOrDefault(function, List.of());
    }

    /** Fonction dont le bloc contient la ligne, ou null. */
    FunctionDef functionAt(String path, int line) {
        Loaded loaded = load(path);
        if (loaded == null) {
            return null;
        }
        ScopeResolver.Declaration declaration = loaded.scopes().enclosing(loaded.text(), line, loaded.stem());
        return declaration == null ? null : functionsByLocation.get(path + ":" + declaration.line());
    }

    /** Affectations {@code nom = ...} du fichier (champ, variable, {@code this.nom}), hors commentaires. */
    List<Assignment> assignments(String path, String name) {
        Loaded loaded = load(path);
        if (loaded == null) {
            return List.of();
        }
        Pattern pattern = Pattern.compile("(?<![\\w$.])(?:(?:this|self)\\s*\\.\\s*)?" + Pattern.quote(name)
                + "\\s*(?::\\s*[\\w<>\\[\\], .?]+?)?\\s*=(?![=>])\\s*(?<value>[^;\\n]+)");
        List<Assignment> found = new ArrayList<>();
        Matcher matcher = pattern.matcher(loaded.text().content());
        while (matcher.find()) {
            int line = loaded.text().lineOf(matcher.start());
            if (!loaded.commentLines().contains(line)) {
                found.add(new Assignment(stripTrailingComment(matcher.group("value")), line));
            }
        }
        return found;
    }

    Optional<SourceText> text(String path) {
        return Optional.ofNullable(load(path)).map(Loaded::text);
    }

    private void indexDeclarations() {
        for (String path : files.keySet()) {
            Loaded loaded = read(path);
            if (loaded == null) {
                continue;
            }
            ConstantResolver.indexInto(constants, loaded.text().content());
            for (ScopeResolver.Declaration declaration : loaded.scopes().declarations(loaded.text(), loaded.stem())) {
                List<String> parameters = parameters(loaded.text(), declaration);
                int required = parameters == null ? 0 : (int) parameters.stream().filter(p -> !p.endsWith("=")).count();
                List<String> names = parameters == null ? null
                        : parameters.stream().map(p -> p.endsWith("=") ? p.substring(0, p.length() - 1) : p).toList();
                FunctionDef function = new FunctionDef(path, declaration, names, required);
                functionsByName.computeIfAbsent(declaration.name(), k -> new ArrayList<>()).add(function);
                functionsByLocation.put(path + ":" + declaration.line(), function);
            }
        }
    }

    private void indexCalls() {
        if (functionsByName.isEmpty()) {
            return;
        }
        for (String path : files.keySet()) {
            Loaded loaded = load(path);
            if (loaded == null) {
                continue;
            }
            String content = loaded.text().content();
            Map<String, String> types = new HashMap<>();
            Matcher matcher = CALL.matcher(content);
            while (matcher.find()) {
                List<FunctionDef> candidates = functionsByName.get(matcher.group("name"));
                if (candidates == null) {
                    continue;
                }
                int line = loaded.text().lineOf(matcher.start());
                FunctionDef declaredHere = functionsByLocation.get(path + ":" + line);
                if (loaded.commentLines().contains(line)
                        || (declaredHere != null && declaredHere.declaration().name().equals(matcher.group("name")))) {
                    continue;
                }
                List<String> arguments = arguments(content, matcher.end() - 1);
                if (arguments == null) {
                    continue;
                }
                ScopeResolver.Declaration caller = loaded.scopes().enclosing(loaded.text(), line, loaded.stem());
                String receiver = receiverBefore(content, matcher.start());
                FunctionDef callee = resolve(candidates, receiver, arguments.size(), path, caller, content, types);
                if (callee != null) {
                    Call call = new Call(path, line, caller == null ? null : caller.qualified(), callee, arguments);
                    calls.add(call);
                    callers.computeIfAbsent(callee, k -> new ArrayList<>()).add(call);
                }
            }
        }
    }

    /** Déclaration désignée par l'appel, ou null si plusieurs restent possibles. */
    private static FunctionDef resolve(List<FunctionDef> candidates, String receiver, int argumentCount, String path,
                                       ScopeResolver.Declaration caller, String content, Map<String, String> types) {
        List<FunctionDef> matching = candidates.stream().filter(f -> f.accepts(argumentCount)).toList();
        List<FunctionDef> chosen;
        if (NEW.equals(receiver)) {
            chosen = matching.stream()
                    .filter(f -> f.declaration().name().equals(f.declaration().container())).toList();
        } else if (receiver.isEmpty() || SELF.contains(receiver)) {
            chosen = matching.stream().filter(f -> f.path().equals(path) && caller != null
                    && f.declaration().container().equals(caller.container())).toList();
            if (chosen.isEmpty()) {
                chosen = matching.stream().filter(f -> f.path().equals(path)).toList();
            }
            if (chosen.isEmpty() && receiver.isEmpty()) {
                chosen = matching;
            }
        } else if (CHAINED.equals(receiver)) {
            // a().b() : le type de a() est inconnu.
            chosen = List.of();
        } else {
            // Classe.methode() ou variable d'une classe du projet ; une variable d'un type de bibliothèque
            // (Javalin app, Supplier s) ou de type inconnu n'est pas reliée à un homonyme du projet.
            String type = matching.stream().anyMatch(f -> f.declaration().container().equals(receiver))
                    ? receiver : types.computeIfAbsent(receiver, r -> Objects.requireNonNullElse(typeOf(r, content), ""));
            chosen = matching.stream().filter(f -> f.declaration().container().equals(type)).toList();
        }
        return chosen.size() == 1 ? chosen.get(0) : null;
    }

    /** "new", "this", "()" (appel chaîné), un identifiant, ou "" sans receveur. */
    private static String receiverBefore(String content, int nameStart) {
        int i = skipSpacesBackward(content, nameStart - 1);
        boolean dotted = i >= 0 && content.charAt(i) == '.';
        boolean arrow = i >= 1 && (content.startsWith("->", i - 1) || content.startsWith("::", i - 1));
        if (!dotted && !arrow) {
            int end = i + 1;
            int start = end;
            while (start > 0 && Character.isLetter(content.charAt(start - 1))) {
                start--;
            }
            return content.substring(start, end).equals(NEW) ? NEW : "";
        }
        i = skipSpacesBackward(content, dotted ? i - 1 : i - 2);
        if (i < 0) {
            return CHAINED;
        }
        if (content.charAt(i) == ')' || content.charAt(i) == ']') {
            return CHAINED;
        }
        int end = i + 1;
        while (i >= 0 && (Character.isLetterOrDigit(content.charAt(i)) || content.charAt(i) == '_'
                || content.charAt(i) == '$')) {
            i--;
        }
        String receiver = content.substring(i + 1, end);
        return receiver.startsWith("$this") ? "this" : receiver.replace("$", "").isEmpty() ? CHAINED : receiver;
    }

    private static int skipSpacesBackward(String content, int from) {
        int i = from;
        while (i >= 0 && Character.isWhitespace(content.charAt(i))) {
            i--;
        }
        return i;
    }

    /** Type déclaré d'une variable du fichier : {@code Classe v}, {@code v: Classe}, {@code v = new Classe(}. */
    private static String typeOf(String variable, String content) {
        String name = Pattern.quote(variable);
        for (String template : List.of(
                "(?<![\\w$.])(?<type>[A-Z][\\w$]*)(?:<[^<>;\\n]*>)?(?:\\[\\])*\\s+" + name + "\\s*[=;,)]",
                "(?<![\\w$.])" + name + "\\s*:\\s*(?<type>[A-Z][\\w$]*)",
                "(?<![\\w$.])" + name + "\\s*=\\s*(?:new\\s+)?(?<type>[A-Z][\\w$]*)\\s*[(<]")) {
            Matcher matcher = Pattern.compile(template).matcher(content);
            if (matcher.find()) {
                return matcher.group("type");
            }
        }
        return null;
    }

    /**
     * Noms des paramètres de la déclaration (suffixe "=" quand le paramètre a une valeur par défaut), ou null si
     * la signature n'est pas lisible. Le premier paramètre implicite d'une méthode Python est retiré.
     */
    private static List<String> parameters(SourceText text, ScopeResolver.Declaration declaration) {
        StringBuilder signature = new StringBuilder();
        int last = Math.min(text.lineCount(), declaration.line() + ScopeResolver.MAX_SIGNATURE_LINES);
        for (int i = declaration.line(); i <= last; i++) {
            signature.append(text.line(i)).append('\n');
        }
        Matcher name = Pattern.compile("(?<![\\w$])" + Pattern.quote(declaration.name()) + "\\s*\\(")
                .matcher(signature);
        if (!name.find()) {
            return null;
        }
        List<String> raw = arguments(signature.toString(), name.end() - 1);
        if (raw == null) {
            return null;
        }
        List<String> names = new ArrayList<>();
        for (String parameter : raw) {
            String parsed = parameterName(parameter);
            if (parsed == null) {
                return null;
            }
            names.add(parsed);
        }
        if (!names.isEmpty() && IMPLICIT_PARAMETERS.contains(names.get(0))) {
            names.remove(0);
        }
        return names;
    }

    /** "final String algo" -> "algo", "algo: String = \"x\"" -> "algo=", "$algo" -> "$algo". */
    private static String parameterName(String parameter) {
        String text = ANNOTATION.matcher(parameter).replaceAll("").trim();
        int equals = topLevelIndex(text, '=');
        boolean hasDefault = equals >= 0;
        if (hasDefault) {
            text = text.substring(0, equals).trim();
        }
        int colon = topLevelIndex(text, ':');
        if (colon >= 0) {
            text = text.substring(0, colon);
        }
        Matcher identifier = Pattern.compile("\\$?[A-Za-z_][\\w$]*").matcher(text);
        String name = null;
        while (identifier.find()) {
            name = identifier.group();
        }
        return name == null ? null : hasDefault ? name + "=" : name;
    }

    private static int topLevelIndex(String text, char wanted) {
        int depth = 0;
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            if (c == '<' || c == '(' || c == '[' || c == '{') {
                depth++;
            } else if (c == '>' || c == ')' || c == ']' || c == '}') {
                depth--;
            } else if (c == wanted && depth == 0) {
                return i;
            }
        }
        return -1;
    }

    /**
     * Argument complet qui commence à {@code start}, jusqu'à la virgule ou la parenthèse fermante de premier
     * niveau : {@code String.valueOf(algo)} là où une règle n'a capturé que {@code String.valueOf}.
     */
    static String argumentAt(String content, int start) {
        List<String> rest = arguments(content, start - 1);
        return rest == null || rest.isEmpty() ? null : rest.get(0);
    }

    /**
     * Arguments d'un appel dont la parenthèse ouvrante est à {@code open}, découpés aux virgules de premier niveau
     * (chaînes, parenthèses, crochets et accolades respectés) ; null si la parenthèse n'est pas refermée.
     */
    static List<String> arguments(String content, int open) {
        List<String> arguments = new ArrayList<>();
        int depth = 0;
        int start = open + 1;
        char quote = 0;
        for (int i = open + 1; i < content.length(); i++) {
            char c = content.charAt(i);
            if (quote != 0) {
                if (c == '\\') {
                    i++;
                } else if (c == quote) {
                    quote = 0;
                }
                continue;
            }
            switch (c) {
                case '"', '\'', '`' -> quote = c;
                case '(', '[', '{' -> depth++;
                case ')', ']', '}' -> {
                    if (depth == 0) {
                        String lastArgument = content.substring(start, i).trim();
                        if (!lastArgument.isEmpty() || !arguments.isEmpty()) {
                            arguments.add(lastArgument);
                        }
                        return arguments;
                    }
                    depth--;
                }
                case ',' -> {
                    if (depth == 0) {
                        arguments.add(content.substring(start, i).trim());
                        start = i + 1;
                    }
                }
                default -> {
                }
            }
        }
        return null;
    }

    private static String stripTrailingComment(String value) {
        int comment = value.indexOf("//");
        int hash = value.indexOf(" #");
        int cut = comment >= 0 && !value.substring(0, comment).contains("\"") ? comment : hash >= 0 ? hash : -1;
        return (cut >= 0 ? value.substring(0, cut) : value).trim();
    }

    private Loaded load(String path) {
        Loaded loaded = cache.get(path);
        if (loaded == null) {
            loaded = read(path);
            if (loaded != null) {
                cache.put(path, loaded);
            }
        }
        return loaded;
    }

    private Loaded read(String path) {
        ScannedFile file = files.get(path);
        if (file == null) {
            return null;
        }
        try {
            Optional<SourceText> text = SourceText.load(root.resolve(path));
            if (text.isEmpty()) {
                return null;
            }
            RulePack pack = scopePack.apply(file.language());
            ScopeResolver scopes = new ScopeResolver(pack.functionPatterns(), pack.classPatterns(),
                    ScopeResolver.BlockStyle.of(pack.blockStyle()));
            String name = path.substring(path.lastIndexOf('/') + 1);
            int dot = name.indexOf('.');
            Set<Integer> commentLines = new HashSet<>();
            for (int i = 1; i <= text.get().lineCount(); i++) {
                if (text.get().isCommentLine(i, commentPrefixes)) {
                    commentLines.add(i);
                }
            }
            return new Loaded(text.get(), scopes, dot > 0 ? name.substring(0, dot) : name, commentLines);
        } catch (IOException e) {
            LOG.debug("Fichier ignoré pour l'index du code : {}", path);
            return null;
        }
    }
}
