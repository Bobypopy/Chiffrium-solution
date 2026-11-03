package com.chiffrium.infrastructure.rules;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Code d'un notebook Jupyter ({@code .ipynb}) rendu lisible par les règles sans changer la numérotation : chaque
 * ligne d'une cellule de code ({@code    "h = hashlib.md5(data)\n",}) est remplacée, à sa place, par le code
 * qu'elle contient. Les autres lignes (texte, sorties, métadonnées) restent telles quelles : un secret affiché
 * dans une sortie est toujours trouvé.
 */
final class NotebookText {

    private static final Pattern CELL_TYPE = Pattern.compile("\"cell_type\"\\s*:\\s*\"(?<type>\\w+)\"");
    private static final Pattern SOURCE_START = Pattern.compile("^\\s*\"source\"\\s*:\\s*\\[\\s*$");
    private static final Pattern SOURCE_LINE = Pattern.compile("^\\s*\"(?<code>(?:[^\"\\\\]|\\\\.)*)\"\\s*,?\\s*$");
    private static final Pattern SOURCE_END = Pattern.compile("^\\s*][,\\s]*$");

    private NotebookText() {
    }

    static boolean isNotebook(String fileName) {
        return fileName.toLowerCase(java.util.Locale.ROOT).endsWith(".ipynb");
    }

    static String codeInPlace(String json) {
        String[] lines = json.split("\n", -1);
        boolean code = false;
        boolean inSource = false;
        for (int i = 0; i < lines.length; i++) {
            String line = lines[i];
            Matcher type = CELL_TYPE.matcher(line);
            if (type.find()) {
                code = type.group("type").equals("code");
            }
            if (inSource) {
                Matcher source = SOURCE_LINE.matcher(line);
                if (source.matches()) {
                    lines[i] = unescape(source.group("code")).replace("\n", "").replace("\r", "");
                } else if (SOURCE_END.matcher(line).matches()) {
                    inSource = false;
                }
            } else if (code && SOURCE_START.matcher(line).matches()) {
                inSource = true;
            }
        }
        return String.join("\n", lines);
    }

    /** Chaîne JSON sans ses échappements ({@code \"}, {@code \\}, {@code \n}, {@code é}...). */
    private static String unescape(String text) {
        StringBuilder out = new StringBuilder(text.length());
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            if (c != '\\' || i + 1 >= text.length()) {
                out.append(c);
                continue;
            }
            char next = text.charAt(++i);
            switch (next) {
                case 'n' -> out.append('\n');
                case 't' -> out.append('\t');
                case 'r' -> out.append('\r');
                case 'b', 'f' -> { }
                case 'u' -> {
                    if (i + 4 < text.length()) {
                        out.append((char) Integer.parseInt(text.substring(i + 1, i + 5), 16));
                        i += 4;
                    }
                }
                default -> out.append(next);
            }
        }
        return out.toString();
    }
}
