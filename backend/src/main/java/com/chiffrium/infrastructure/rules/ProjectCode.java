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
 * Code d'un paquet de règles à l'échelle du projet : fonctions déclarées, appels entre elles, affectations,
 * retours et boucles. Sert au graphe quand cdxgen ne fournit pas les appels (langages autres que Java et Python,
 * ligne de commande) et à la trace des valeurs transmises d'une fonction à l'autre ({@link ValueTracer}).
 *
 * <p>Un appel est relié à sa déclaration par le nom, le receveur ({@code bc.go()} avec {@code Classe bc},
 * {@code Classe.go()}, {@code this.go()}, {@code new Classe()}, {@code super(...)}) et le nombre d'arguments.
 * Un appel ambigu (homonymes indiscernables, receveur d'un type de bibliothèque) n'est pas relié : mieux vaut
 * un lien absent qu'un lien faux.
 */
final class ProjectCode {

    private static final Logger LOG = LoggerFactory.getLogger(ProjectCode.class);

    private static final Pattern CALL = Pattern.compile("(?<![\\w$])(?<name>[A-Za-z_$][\\w$]*)\\s*\\(");
    private static final Pattern ANNOTATION = Pattern.compile("@[\\w.]+(?:\\([^)]*\\))?\\s*");
    private static final Pattern RETURN = Pattern.compile("(?<![\\w$])return\\s+(?<value>[^;\\n]+)");
    /** Corps d'une fonction à expression : {@code fun algo() = "AES"}, {@code def algo = "AES"}. */
    private static final Pattern EXPRESSION_BODY = Pattern.compile("\\)\\s*(?::\\s*[\\w<>?.\\[\\], ]+)?\\s*=(?![=>])\\s*(?<value>[^\\n;{]+)$");
    private static final Set<String> SELF = Set.of("this", "self");
    /** Noms des constructeurs déclarés à part du nom de la classe (JavaScript, TypeScript, Python, PHP). */
    private static final Set<String> CONSTRUCTOR_NAMES = Set.of("constructor", "__init__", "__construct");
    /** Appels d'un autre constructeur depuis un constructeur. */
    private static final String SUPER = "super";
    private static final String THIS = "this";
    /** Premier paramètre implicite d'une méthode Python : absent des arguments de l'appel. */
    private static final Set<String> IMPLICIT_PARAMETERS = Set.of("self", "cls");
    private static final String NEW = "new";
    private static final String CHAINED = "()";
    /** Collection parcourue, en fin de texte avant {@code .forEach(} : {@code algos}, {@code List.of("A", "B")}. */
    private static final Pattern FOR_EACH_RECEIVER = Pattern.compile("(?<value>[\\w$.]+(?:\\([^()\\n]*\\))?)\\s*$");
    private static final int TEXT_CACHE_SIZE = 256;
    /** Lignes où chercher un appel passé en argument d'un appel écrit sur plusieurs lignes. */
    private static final int MAX_ARGUMENT_LINES = 10;
    private static final int MAX_BODY_LINES = 400;

    /**
     * Fonction déclarée.
     *
     * @param parameters noms des paramètres, null si la signature n'a pas pu être lue
     * @param types      types déclarés des paramètres (null quand le langage n'en écrit pas)
     * @param required   nombre de paramètres sans valeur par défaut
     */
    record FunctionDef(String path, ScopeResolver.Declaration declaration, List<String> parameters,
                       List<String> types, int required) {

        String qualified() {
            return declaration.qualified();
        }

        boolean accepts(int arguments) {
            return parameters == null || (arguments >= required && arguments <= parameters.size());
        }

        /** Faux si un argument de type connu ne peut pas aller dans le paramètre (byte[] dans un PrivateKey). */
        boolean accepts(List<String> argumentTypes) {
            if (types == null) {
                return true;
            }
            for (int i = 0; i < Math.min(types.size(), argumentTypes.size()); i++) {
                if (!TypeKind.compatible(argumentTypes.get(i), types.get(i))) {
                    return false;
                }
            }
            return true;
        }

        boolean isConstructor() {
            return declaration.name().equals(declaration.container()) || CONSTRUCTOR_NAMES.contains(declaration.name());
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

    /** Expression qui donne sa valeur à un nom (affectation, retour, élément parcouru) et sa ligne. */
    record Assignment(String expression, int line) {
    }

    private record Loaded(SourceText text, ScopeResolver scopes, String stem, Set<Integer> commentLines) {
    }

    private final Path root;
    private final Map<String, ScannedFile> files = new LinkedHashMap<>();
    private final Function<Language, RulePack> scopePack;
    private final Map<String, List<String>> constants = new HashMap<>();
    private final Map<String, List<FunctionDef>> functionsByName = new HashMap<>();
    private final Map<String, FunctionDef> functionsByLocation = new HashMap<>();
    private final Map<String, List<FunctionDef>> constructorsByClass = new HashMap<>();
    private final List<Call> calls = new ArrayList<>();
    private final Map<FunctionDef, List<Call>> callers = new HashMap<>();
    /** Appels entre surcharges de même arité d'une classe : pas de lien dans le graphe, mais suivis par la trace. */
    private final Map<FunctionDef, List<Call>> overloadCallers = new HashMap<>();
    private final Map<String, List<Call>> callsByLocation = new HashMap<>();
    /** Affectations et boucles déjà cherchées, par fichier et par nom : la trace repose souvent les mêmes questions. */
    private final Map<String, List<Assignment>> lookups = new HashMap<>();
    private final Map<String, Loaded> cache = new LinkedHashMap<>(16, 0.75f, true) {
        @Override
        protected boolean removeEldestEntry(Map.Entry<String, Loaded> eldest) {
            return size() > TEXT_CACHE_SIZE;
        }
    };

    private ProjectCode(Path root, List<ScannedFile> files, Function<Language, RulePack> scopePack) {
        this.root = root;
        files.forEach(f -> this.files.put(f.path(), f));
        this.scopePack = scopePack;
    }

    /**
     * Lit les fichiers deux fois : déclarations et constantes d'abord, puis les appels, que l'on ne peut relier
     * qu'une fois toutes les déclarations connues. Seul l'index est gardé en mémoire, pas le texte.
     *
     * @param scopePack paquet qui décrit la syntaxe (déclarations, commentaires) de chaque langage
     */
    static ProjectCode load(Path root, List<ScannedFile> files, Function<Language, RulePack> scopePack) {
        ProjectCode code = new ProjectCode(root, files, scopePack);
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

    /**
     * Appels qui peuvent transmettre une valeur à la fonction : ceux qui la désignent, et ceux qui hésitent
     * entre elle et une surcharge de même arité de la même classe ({@code verify(String, ...)} et
     * {@code verify(byte[], ...)}) : la valeur passe par l'une ou l'autre, et l'une délègue souvent à l'autre.
     */
    List<Call> callersOf(FunctionDef function) {
        List<Call> all = new ArrayList<>(callers.getOrDefault(function, List.of()));
        all.addAll(overloadCallers.getOrDefault(function, List.of()));
        return all;
    }

    /**
     * Appel de la fonction {@code name} du projet écrit à cette ligne, ou dans les lignes suivantes quand il est
     * passé en argument d'un appel écrit sur plusieurs lignes ; vide s'il n'a pas été relié.
     */
    Optional<Call> callAt(String path, int line, String name) {
        for (int l = line; l <= line + MAX_ARGUMENT_LINES; l++) {
            Optional<Call> call = callsByLocation.getOrDefault(path + ":" + l, List.of()).stream()
                    .filter(c -> c.callee().declaration().name().equals(name))
                    .findFirst();
            if (call.isPresent()) {
                return call;
            }
        }
        return Optional.empty();
    }

    /** Constructeur de la classe déclaré dans ce fichier qui a un paramètre de ce nom, ou null. */
    FunctionDef constructorWithParameter(String path, String container, String parameter) {
        List<FunctionDef> candidates = new ArrayList<>(constructorsByClass.getOrDefault(container, List.of()));
        candidates.addAll(functionsByName.getOrDefault(container, List.of()));
        return candidates.stream()
                .filter(f -> f.path().equals(path) && f.isConstructor()
                        && f.declaration().container().equals(container)
                        && f.parameters() != null && f.parameters().contains(parameter))
                .findFirst().orElse(null);
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
        return lookups.computeIfAbsent("=" + path + "|" + name, k -> matches(path, Pattern.compile(
                "(?<![\\w$.])(?:(?:this|self)\\s*\\.\\s*)?" + Pattern.quote(name)
                        + "\\s*(?::\\s*[\\w<>\\[\\], .?]+?)?\\s*=(?![=>])\\s*(?<value>[^;\\n]+)")));
    }

    /**
     * Collections parcourues par une boucle qui donne ses valeurs au nom : {@code for (String a : algos)},
     * {@code for (a in algos)}, {@code for (const a of algos)}, {@code for a in algos:}, {@code algos.forEach(a ->}.
     * Chaque motif commence par un mot fixe ({@code for}, {@code forEach}) : une alternative ouverte par
     * {@code [\w.]+} essayait chaque position du fichier et prenait l'essentiel du temps d'analyse.
     */
    List<Assignment> loops(String path, String name) {
        return lookups.computeIfAbsent("for" + path + "|" + name, k -> {
            String quoted = Pattern.quote(name);
            List<Assignment> found = new ArrayList<>(matches(path, Pattern.compile(
                    "\\bfor\\s*\\(\\s*(?:final\\s+|const\\s+|let\\s+|var\\s+|val\\s+)?(?:[\\w<>\\[\\],.?]+\\s+)?" + quoted
                            + "\\s*(?::|\\bin\\b|\\bof\\b)\\s*(?<value>[^\\n]+)"
                            + "|\\bfor\\s+" + quoted + "\\s+in\\s+(?<value2>[^:\\n]+):")));
            Loaded loaded = load(path);
            if (loaded != null) {
                Matcher forEach = Pattern.compile("\\.\\s*forEach\\s*[({]\\s*\\(?\\s*" + quoted + "\\s*\\)?\\s*(?:->|=>)")
                        .matcher(loaded.text().content());
                while (forEach.find()) {
                    int line = loaded.text().lineOf(forEach.start());
                    String before = loaded.text().content().substring(
                            loaded.text().content().lastIndexOf('\n', forEach.start()) + 1, forEach.start());
                    Matcher receiver = FOR_EACH_RECEIVER.matcher(before);
                    if (receiver.find() && !loaded.commentLines().contains(line)) {
                        found.add(new Assignment(receiver.group("value"), line));
                    }
                }
            }
            return found;
        });
    }

    /** Expressions renvoyées par la fonction : {@code return ...} dans son bloc, ou corps à expression. */
    List<Assignment> returns(FunctionDef function) {
        Loaded loaded = load(function.path());
        if (loaded == null) {
            return List.of();
        }
        List<Assignment> found = new ArrayList<>();
        int start = function.declaration().line();
        Matcher body = EXPRESSION_BODY.matcher(loaded.text().line(start));
        if (body.find()) {
            found.add(new Assignment(body.group("value").trim(), start));
        }
        int last = Math.min(loaded.text().lineCount(), start + MAX_BODY_LINES);
        for (int line = start + 1; line <= last; line++) {
            ScopeResolver.Declaration enclosing = loaded.scopes().enclosing(loaded.text(), line, loaded.stem());
            if (enclosing == null || enclosing.line() < start) {
                break;
            }
            Matcher matcher = RETURN.matcher(loaded.text().line(line));
            if (enclosing.line() == start && !loaded.commentLines().contains(line) && matcher.find()) {
                found.add(new Assignment(stripTrailingComment(matcher.group("value")), line));
            }
        }
        return found;
    }

    Optional<SourceText> text(String path) {
        return Optional.ofNullable(load(path)).map(Loaded::text);
    }

    Language language(String path) {
        ScannedFile file = files.get(path);
        return file == null ? null : file.language();
    }

    private List<Assignment> matches(String path, Pattern pattern) {
        Loaded loaded = load(path);
        if (loaded == null) {
            return List.of();
        }
        List<Assignment> found = new ArrayList<>();
        Matcher matcher = pattern.matcher(loaded.text().content());
        while (matcher.find()) {
            int line = loaded.text().lineOf(matcher.start());
            String value = firstNonNull(matcher, "value", "value2", "value3");
            if (value != null && !loaded.commentLines().contains(line)) {
                found.add(new Assignment(stripTrailingComment(beforeUnbalancedParenthesis(value)), line));
            }
        }
        return found;
    }

    private static String firstNonNull(Matcher matcher, String... groups) {
        for (String group : groups) {
            if (matcher.pattern().namedGroups().containsKey(group) && matcher.group(group) != null) {
                return matcher.group(group);
            }
        }
        return null;
    }

    private void indexDeclarations() {
        for (String path : files.keySet()) {
            Loaded loaded = read(path);
            if (loaded == null) {
                continue;
            }
            ConstantResolver.indexInto(constants, loaded.text().content());
            for (ScopeResolver.Declaration declaration : loaded.scopes().declarations(loaded.text(), loaded.stem())) {
                List<String> raw = rawParameters(loaded.text(), declaration);
                List<String> parameters = raw == null ? null : parameterNames(raw);
                int required = parameters == null ? 0 : (int) parameters.stream().filter(p -> !p.endsWith("=")).count();
                List<String> names = parameters == null ? null
                        : parameters.stream().map(p -> p.endsWith("=") ? p.substring(0, p.length() - 1) : p).toList();
                List<String> types = parameters == null ? null : parameterTypes(raw, parameters.size());
                FunctionDef function = new FunctionDef(path, declaration, names, types, required);
                functionsByName.computeIfAbsent(declaration.name(), k -> new ArrayList<>()).add(function);
                functionsByLocation.put(path + ":" + declaration.line(), function);
                if (CONSTRUCTOR_NAMES.contains(declaration.name())) {
                    constructorsByClass.computeIfAbsent(declaration.container(), k -> new ArrayList<>()).add(function);
                }
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
                String name = matcher.group("name");
                int line = loaded.text().lineOf(matcher.start());
                FunctionDef declaredHere = functionsByLocation.get(path + ":" + line);
                if (loaded.commentLines().contains(line)
                        || (declaredHere != null && declaredHere.declaration().name().equals(name))) {
                    continue;
                }
                String receiver = receiverBefore(content, matcher.start());
                ScopeResolver.Declaration caller = loaded.scopes().enclosing(loaded.text(), line, loaded.stem());
                List<FunctionDef> candidates = candidates(name, receiver, caller, content);
                if (candidates.isEmpty()) {
                    continue;
                }
                List<String> arguments = arguments(content, matcher.end() - 1);
                if (arguments == null) {
                    continue;
                }
                boolean constructorCall = SUPER.equals(name) || THIS.equals(name)
                        || !functionsByName.containsKey(name);
                List<FunctionDef> chosen = choose(candidates, constructorCall ? NEW : receiver, arguments, path,
                        caller, content, types);
                String callerName = caller == null ? null : caller.qualified();
                if (chosen.size() == 1) {
                    Call call = new Call(path, line, callerName, chosen.get(0), arguments);
                    calls.add(call);
                    callers.computeIfAbsent(chosen.get(0), k -> new ArrayList<>()).add(call);
                    callsByLocation.computeIfAbsent(path + ":" + line, k -> new ArrayList<>()).add(call);
                } else if (chosen.size() > 1 && chosen.stream().allMatch(f -> f.path().equals(chosen.get(0).path())
                        && f.declaration().container().equals(chosen.get(0).declaration().container()))) {
                    for (FunctionDef overload : chosen) {
                        overloadCallers.computeIfAbsent(overload, k -> new ArrayList<>())
                                .add(new Call(path, line, callerName, overload, arguments));
                    }
                }
            }
        }
    }

    /**
     * Déclarations que l'appel peut viser : fonctions de ce nom ; constructeurs de la classe parente pour
     * {@code super(...)}, de la classe pour {@code this(...)} ; constructeur nommé à part ({@code __init__},
     * {@code constructor}) pour {@code Classe(...)} et {@code new Classe(...)}.
     */
    private List<FunctionDef> candidates(String name, String receiver, ScopeResolver.Declaration caller,
                                         String content) {
        if ((SUPER.equals(name) || THIS.equals(name)) && receiver.isEmpty() && caller != null) {
            String target = THIS.equals(name) ? caller.container() : parentOf(caller.container(), content);
            return target == null ? List.of() : constructorsOf(target);
        }
        List<FunctionDef> named = functionsByName.get(name);
        if (named != null) {
            return named;
        }
        return (receiver.isEmpty() || NEW.equals(receiver)) ? constructorsByClass.getOrDefault(name, List.of())
                : List.of();
    }

    private List<FunctionDef> constructorsOf(String container) {
        List<FunctionDef> constructors = new ArrayList<>(constructorsByClass.getOrDefault(container, List.of()));
        functionsByName.getOrDefault(container, List.of()).stream()
                .filter(f -> f.declaration().container().equals(container))
                .forEach(constructors::add);
        return constructors;
    }

    private static String parentOf(String container, String content) {
        Matcher matcher = Pattern.compile("\\b(?:class|record)\\s+" + Pattern.quote(container)
                + "\\b[^{;]*?\\bextends\\s+(?<parent>[A-Z][\\w$]*)").matcher(content);
        return matcher.find() ? matcher.group("parent") : null;
    }

    /**
     * Déclarations que l'appel peut encore désigner : une seule pour un appel relié. Entre surcharges de même
     * arité, les types connus des arguments écartent celles qui ne peuvent pas les recevoir.
     */
    private static List<FunctionDef> choose(List<FunctionDef> candidates, String receiver, List<String> arguments,
                                            String path, ScopeResolver.Declaration caller, String content,
                                            Map<String, String> types) {
        List<FunctionDef> matching = candidates.stream().filter(f -> f.accepts(arguments.size())).toList();
        if (matching.size() > 1) {
            List<String> argumentTypes = arguments.stream()
                    .map(a -> types.computeIfAbsent("(" + a, k -> Objects.requireNonNullElse(TypeKind.ofArgument(a, content), "")))
                    .map(t -> t.isEmpty() ? null : t)
                    .toList();
            List<FunctionDef> typed = matching.stream().filter(f -> f.accepts(argumentTypes)).toList();
            matching = typed.isEmpty() ? matching : typed;
        }
        List<FunctionDef> chosen;
        if (NEW.equals(receiver)) {
            chosen = matching.stream().filter(FunctionDef::isConstructor).toList();
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
        return chosen;
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

    /** Classe déclarée d'une variable du fichier : {@code Classe v}, {@code v: Classe}, {@code v = new Classe(}. */
    private static String typeOf(String variable, String content) {
        String type = TypeKind.declared(variable, content, true);
        if (type == null) {
            return null;
        }
        String base = type.replaceAll("<.*", "").replace("[]", "");
        return base.substring(base.lastIndexOf('.') + 1);
    }

    /**
     * Paramètres de la déclaration tels qu'écrits, ou null si la signature n'est pas lisible. Une fonction
     * fléchée ({@code const f = (a, b) => ...}, {@code const f = a => ...}) est lue aussi.
     */
    private static List<String> rawParameters(SourceText text, ScopeResolver.Declaration declaration) {
        StringBuilder signature = new StringBuilder();
        int last = Math.min(text.lineCount(), declaration.line() + ScopeResolver.MAX_SIGNATURE_LINES);
        for (int i = declaration.line(); i <= last; i++) {
            signature.append(text.line(i)).append('\n');
        }
        String quoted = Pattern.quote(declaration.name());
        Matcher name = Pattern.compile("(?<![\\w$])" + quoted + "\\s*(?::[^=\\n]+)?(?:=\\s*(?:async\\s*)?(?:function\\s*)?)?\\(")
                .matcher(signature);
        List<String> raw;
        if (name.find()) {
            raw = arguments(signature.toString(), name.end() - 1);
        } else {
            Matcher single = Pattern.compile("(?<![\\w$])" + quoted + "\\s*=\\s*(?:async\\s+)?(?<param>[\\w$]+)\\s*=>")
                    .matcher(signature);
            raw = single.find() ? List.of(single.group("param")) : null;
        }
        return raw;
    }

    /**
     * Noms des paramètres (suffixe "=" quand le paramètre a une valeur par défaut), ou null si l'un n'est pas
     * lisible. Le premier paramètre implicite d'une méthode Python est retiré.
     */
    private static List<String> parameterNames(List<String> raw) {
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

    /** Types déclarés, alignés sur les noms (le paramètre implicite retiré a aussi son type retiré). */
    private static List<String> parameterTypes(List<String> raw, int count) {
        List<String> types = new ArrayList<>();
        for (String parameter : raw.subList(raw.size() - count, raw.size())) {
            types.add(TypeKind.ofParameter(ANNOTATION.matcher(parameter).replaceAll("").trim()));
        }
        return types;
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

    /** Coupe à la parenthèse qui ferme un en-tête : "List.of(\"A\")) {" -> "List.of(\"A\")". */
    private static String beforeUnbalancedParenthesis(String value) {
        int depth = 0;
        char quote = 0;
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (quote != 0) {
                if (c == quote) {
                    quote = 0;
                }
            } else if (c == '"' || c == '\'') {
                quote = c;
            } else if (c == '(') {
                depth++;
            } else if (c == ')' && --depth < 0) {
                return value.substring(0, i);
            }
        }
        return value;
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
                if (text.get().isCommentLine(i, pack.commentPrefixes())) {
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
