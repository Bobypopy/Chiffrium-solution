package com.chiffrium.infrastructure.rules;

import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Retrouve la fonction englobante d'une ligne : déclaration la plus proche au-dessus <b>dont le bloc
 * contient encore la ligne</b> (profondeur d'accolades pour les langages à accolades, indentation pour
 * Python et Ruby), qualifiée par la classe (ou, à défaut, par le nom du fichier) : "Classe.méthode".
 * Une ligne au niveau du module (constante, variable globale, attribut de classe) n'a pas de fonction.
 */
final class ScopeResolver {

    static final int MAX_LOOKBACK_LINES = 400;
    /** Nombre de lignes tolérées entre une déclaration et l'accolade qui ouvre son bloc. */
    static final int MAX_SIGNATURE_LINES = 5;
    private static final String NAME_GROUP = "name";
    /**
     * Forme "déroulée" et possessive : la récursion du moteur ne dépend que du nombre d'échappements, pas de la
     * longueur de la chaîne (une alternative répétée caractère par caractère débordait la pile sur les longs
     * vecteurs de test, ex. Bouncy Castle).
     */
    private static final Pattern STRING_OR_COMMENT = Pattern.compile(
            "\"[^\"\\\\]*+(?:\\\\.[^\"\\\\]*+)*+\"|'[^'\\\\]*+(?:\\\\.[^'\\\\]*+)*+'|`[^`]*+`|//.*$");
    private static final Set<String> NOT_FUNCTIONS = Set.of(
            "if", "for", "while", "switch", "catch", "return", "new", "else", "do", "try", "synchronized",
            "sizeof", "foreach", "using", "lock", "match", "when", "elif", "with");

    /** Manière dont les blocs sont délimités dans le langage. */
    enum BlockStyle {
        BRACES, INDENT;

        static BlockStyle of(String value) {
            return "indent".equalsIgnoreCase(value) ? INDENT : BRACES;
        }
    }

    private final List<Pattern> functionPatterns;
    private final List<Pattern> classPatterns;
    private final BlockStyle style;
    private int[] depthAtLineStart;

    ScopeResolver(List<Pattern> functionPatterns, List<Pattern> classPatterns, BlockStyle style) {
        this.functionPatterns = functionPatterns;
        this.classPatterns = classPatterns;
        this.style = style;
    }

    /**
     * @param fileStem nom du fichier sans extension, utilisé si aucune classe n'est trouvée
     * @return "Conteneur.fonction", ou null si aucune fonction n'englobe la ligne
     */
    String qualifiedFunction(SourceText text, int line, String fileStem) {
        int lowest = Math.max(1, line - MAX_LOOKBACK_LINES);
        for (int i = line; i >= lowest; i--) {
            String function = find(functionPatterns, text.line(i));
            if (function == null) {
                continue;
            }
            if (!encloses(text, i, line)) {
                return null;
            }
            String container = null;
            int lowestClass = Math.max(1, i - MAX_LOOKBACK_LINES);
            for (int c = i; c >= lowestClass && container == null; c--) {
                container = find(classPatterns, text.line(c));
            }
            return (container != null ? container : fileStem) + "." + function;
        }
        return null;
    }

    /** Vrai si le bloc ouvert par la déclaration de la ligne {@code declaration} contient {@code line}. */
    private boolean encloses(SourceText text, int declaration, int line) {
        if (declaration == line) {
            return true;
        }
        return style == BlockStyle.INDENT ? enclosesByIndent(text, declaration, line)
                : enclosesByBraces(text, declaration, line);
    }

    /**
     * Le bloc est ouvert quand la profondeur dépasse celle de la déclaration (accolade sur la même ligne ou,
     * style Allman, sur une des lignes suivantes) ; il est fermé dès qu'elle y redescend.
     */
    private boolean enclosesByBraces(SourceText text, int declaration, int line) {
        int[] depths = depths(text);
        int base = depths[declaration - 1];
        boolean opened = false;
        for (int k = declaration + 1; k <= line; k++) {
            if (depths[k - 1] > base) {
                opened = true;
            } else if (opened || k - declaration > MAX_SIGNATURE_LINES) {
                return false;
            }
        }
        return opened;
    }

    private static boolean enclosesByIndent(SourceText text, int declaration, int line) {
        int base = indentation(text.line(declaration));
        for (int k = declaration + 1; k <= line; k++) {
            String current = text.line(k);
            if (!current.isBlank() && indentation(current) <= base) {
                return false;
            }
        }
        return true;
    }

    /** Profondeur d'accolades au début de chaque ligne (chaînes et commentaires de ligne ignorés), calculée une fois. */
    private int[] depths(SourceText text) {
        if (depthAtLineStart == null) {
            depthAtLineStart = new int[text.lineCount()];
            int depth = 0;
            for (int i = 1; i <= text.lineCount(); i++) {
                depthAtLineStart[i - 1] = depth;
                String code = STRING_OR_COMMENT.matcher(text.line(i)).replaceAll("");
                for (int c = 0; c < code.length(); c++) {
                    char ch = code.charAt(c);
                    if (ch == '{') {
                        depth++;
                    } else if (ch == '}' && depth > 0) {
                        depth--;
                    }
                }
            }
        }
        return depthAtLineStart;
    }

    private static int indentation(String line) {
        int count = 0;
        while (count < line.length() && Character.isWhitespace(line.charAt(count))) {
            count++;
        }
        return count;
    }

    private static String find(List<Pattern> patterns, String line) {
        for (Pattern pattern : patterns) {
            Matcher matcher = pattern.matcher(line);
            if (matcher.find()) {
                String name = matcher.group(NAME_GROUP);
                if (name != null && !NOT_FUNCTIONS.contains(name)) {
                    return name;
                }
            }
        }
        return null;
    }
}
