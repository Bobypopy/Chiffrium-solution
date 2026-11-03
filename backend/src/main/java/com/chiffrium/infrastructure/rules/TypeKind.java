package com.chiffrium.infrastructure.rules;

import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Nature d'un type (tableau, primitif, chaîne, objet), juste assez pour départager deux surcharges de même
 * arité : un {@code byte[]} ne va pas dans un {@code PrivateKey}, une {@code String} pas dans un {@code byte[]}.
 * Ce n'est pas un vérificateur de types : un type inconnu, un objet ou un paramètre générique acceptent tout.
 */
enum TypeKind {
    ARRAY, PRIMITIVE, STRING, OBJECT;

    private static final Set<String> PRIMITIVES = Set.of("byte", "short", "int", "long", "float", "double",
            "boolean", "char", "Byte", "Short", "Integer", "Long", "Float", "Double", "Boolean", "Character", "Int",
            "number", "bool");
    private static final Set<String> STRINGS = Set.of("String", "CharSequence", "str", "string");
    private static final Set<String> ARRAYS = Set.of("ByteArray", "CharArray", "IntArray", "bytes", "bytearray",
            "Uint8Array", "Buffer");
    /** Paramètres qui reçoivent n'importe quoi. */
    private static final Set<String> ANY = Set.of("Object", "Any", "any", "unknown", "object", "var");
    private static final Set<String> KEYWORDS = Set.of("return", "new", "throw", "else", "case", "yield",
            "instanceof", "in", "of", "await", "import", "package", "goto", "assert");
    private static final Pattern IDENTIFIER = Pattern.compile("^(?:(?:this|self)\\s*\\.\\s*)?(?<name>[A-Za-z_$][\\w$]*)$");
    private static final Pattern NEW = Pattern.compile("^new\\s+(?<type>[\\w.]+)\\s*(?<array>\\[)?");
    private static final Pattern NUMBER = Pattern.compile("^-?\\d+[lLfFdD]?$");
    private static final Pattern TYPE_BEFORE = Pattern.compile(
            "(?<![\\w$.])(?<type>[A-Za-z_][\\w$.]*(?:<[^<>;\\n]*>)?(?:\\[\\])*)\\s+$");
    private static final Pattern AFTER_DECLARED = Pattern.compile("\\s*[=;,)]");
    private static final Pattern TYPE_AFTER_COLON = Pattern.compile("\\s*:\\s*(?<type>[A-Za-z_][\\w$.<>\\[\\]]*)");
    private static final Pattern CREATED_AFTER = Pattern.compile("\\s*=\\s*(?:new\\s+)?(?<type>[A-Z][\\w$]*)\\s*[(<]");

    static boolean compatible(String argumentType, String parameterType) {
        if (argumentType == null || parameterType == null || ANY.contains(parameterType)
                || parameterType.matches("[A-Z]")) {
            return true;
        }
        return of(argumentType) == of(parameterType);
    }

    static TypeKind of(String type) {
        if (type.endsWith("[]") || ARRAYS.contains(type) || type.startsWith("Array<")) {
            return ARRAY;
        }
        if (PRIMITIVES.contains(type)) {
            return PRIMITIVE;
        }
        return STRINGS.contains(type) ? STRING : OBJECT;
    }

    /** Type écrit d'un paramètre ({@code final byte[] key}, {@code key: ByteArray}), null s'il n'y en a pas. */
    static String ofParameter(String parameter) {
        String text = parameter;
        int equals = text.indexOf('=');
        if (equals >= 0) {
            text = text.substring(0, equals);
        }
        int colon = text.indexOf(':');
        String type;
        if (colon >= 0) {
            type = text.substring(colon + 1);
        } else {
            Matcher last = Pattern.compile("[\\w$]+\\s*$").matcher(text.trim());
            type = last.find() ? text.trim().substring(0, last.start()) : "";
        }
        return simplify(type.replaceAll("\\b(?:final|const|readonly|private|public|protected|val|var|in|out)\\s+", ""));
    }

    /** Type d'un argument quand il se lit sans analyse : littéral, {@code new}, variable déclarée dans le fichier. */
    static String ofArgument(String argument, String content) {
        String text = argument.trim();
        if (text.startsWith("\"") || text.startsWith("'")) {
            return "String";
        }
        if (NUMBER.matcher(text).matches()) {
            return "int";
        }
        if (text.equals("true") || text.equals("false")) {
            return "boolean";
        }
        Matcher created = NEW.matcher(text);
        if (created.find()) {
            return simplify(created.group("type")) + (created.group("array") != null ? "[]" : "");
        }
        Matcher identifier = IDENTIFIER.matcher(text);
        return identifier.matches() ? declaredType(identifier.group("name"), content) : null;
    }

    private static String declaredType(String name, String content) {
        String type = declared(name, content, false);
        return type == null ? null : simplify(type);
    }

    /**
     * Type écrit à la déclaration d'une variable du fichier : {@code Type v =|;|,|)}, {@code v: Type}, et pour
     * une classe seulement {@code v = new Type(} / {@code v = Type(}. La recherche part des occurrences du nom
     * puis lit le texte voisin : un motif qui commence par le type essaierait chaque mot du fichier.
     *
     * @param classOnly ne retenir qu'un type qui commence par une majuscule (receveur d'un appel de méthode)
     */
    static String declared(String name, String content, boolean classOnly) {
        Matcher occurrence = Pattern.compile("(?<![\\w$.])" + Pattern.quote(name) + "(?![\\w$])").matcher(content);
        String assigned = null;
        while (occurrence.find()) {
            int lineStart = content.lastIndexOf('\n', occurrence.start()) + 1;
            int lineEnd = content.indexOf('\n', occurrence.end());
            String before = content.substring(lineStart, occurrence.start());
            String after = content.substring(occurrence.end(), lineEnd < 0 ? content.length() : lineEnd);
            Matcher typed = TYPE_BEFORE.matcher(before);
            if (typed.find() && AFTER_DECLARED.matcher(after).lookingAt() && !KEYWORDS.contains(typed.group("type"))
                    && (!classOnly || Character.isUpperCase(typed.group("type").charAt(0)))) {
                return typed.group("type");
            }
            Matcher annotated = TYPE_AFTER_COLON.matcher(after);
            if (annotated.lookingAt() && (!classOnly || Character.isUpperCase(annotated.group("type").charAt(0)))) {
                return annotated.group("type");
            }
            Matcher created = CREATED_AFTER.matcher(after);
            if (classOnly && assigned == null && created.lookingAt()) {
                assigned = created.group("type");
            }
        }
        return assigned;
    }

    /** "java.security.PrivateKey" -> "PrivateKey", "List<String>" -> "List", "String..." -> "String[]". */
    private static String simplify(String type) {
        String text = type.trim().replace("...", "[]").replaceAll("<.*>", "").replace("?", "").replace(" ", "");
        if (text.isEmpty()) {
            return null;
        }
        String arrays = text.endsWith("[]") ? text.substring(text.indexOf("[]")) : "";
        String base = arrays.isEmpty() ? text : text.substring(0, text.indexOf("[]"));
        return base.substring(base.lastIndexOf('.') + 1) + arrays;
    }
}
