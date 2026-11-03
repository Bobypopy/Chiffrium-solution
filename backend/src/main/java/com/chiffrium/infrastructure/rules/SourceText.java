package com.chiffrium.infrastructure.rules;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.BitSet;
import java.util.List;
import java.util.Optional;

/**
 * Contenu d'un fichier source avec index des débuts de ligne (conversion position -> ligne/colonne).
 */
public final class SourceText {

    private static final int MAX_SNIPPET_LENGTH = 200;
    /** Au-delà, le fichier est considéré comme minifié ou généré (lignes illisibles, faux positifs). */
    static final int MAX_AVERAGE_LINE_LENGTH = 500;
    private static final int BINARY_PROBE_BYTES = 8_192;

    /** Bloc de commentaire de PowerShell, reconnu quand le langage déclare ce début de commentaire. */
    private static final String BLOCK_OPEN = "<#";
    private static final String BLOCK_CLOSE = "#>";

    private final String content;
    private final int[] lineStarts;
    /** Calculé à la première demande (fichier PowerShell seulement). */
    private BitSet blockLines;

    public SourceText(String content) {
        this.content = content;
        List<Integer> starts = new ArrayList<>();
        starts.add(0);
        for (int i = 0; i < content.length(); i++) {
            if (content.charAt(i) == '\n') {
                starts.add(i + 1);
            }
        }
        this.lineStarts = starts.stream().mapToInt(Integer::intValue).toArray();
    }

    /**
     * Lit un fichier texte (UTF-8).
     *
     * @return vide pour un fichier binaire (octet nul) ou minifié
     */
    public static Optional<SourceText> load(Path file) throws IOException {
        Optional<SourceText> text = of(Files.readAllBytes(file));
        // Notebook Jupyter : le code des cellules, sorti de ses guillemets JSON, à la même ligne.
        return file.getFileName() != null && NotebookText.isNotebook(file.getFileName().toString())
                ? text.map(t -> new SourceText(NotebookText.codeInPlace(t.content()))) : text;
    }

    /**
     * Même lecture à partir d'un contenu déjà chargé (ex. version d'un fichier dans l'historique Git).
     *
     * @return vide pour un contenu binaire (octet nul) ou minifié
     */
    public static Optional<SourceText> of(byte[] bytes) {
        int probe = Math.min(bytes.length, BINARY_PROBE_BYTES);
        for (int i = 0; i < probe; i++) {
            if (bytes[i] == 0) {
                return Optional.empty();
            }
        }
        SourceText text = new SourceText(new String(bytes, StandardCharsets.UTF_8));
        if (text.content().length() / Math.max(1, text.lineCount()) > MAX_AVERAGE_LINE_LENGTH) {
            return Optional.empty();
        }
        return Optional.of(text);
    }

    public String content() {
        return content;
    }

    public int lineCount() {
        return lineStarts.length;
    }

    /** Numéro de ligne 1-based d'une position. */
    public int lineOf(int offset) {
        int low = 0;
        int high = lineStarts.length - 1;
        while (low < high) {
            int mid = (low + high + 1) >>> 1;
            if (lineStarts[mid] <= offset) {
                low = mid;
            } else {
                high = mid - 1;
            }
        }
        return low + 1;
    }

    /** Colonne 1-based d'une position. */
    public int columnOf(int offset) {
        return offset - lineStarts[lineOf(offset) - 1] + 1;
    }

    /** Texte de la ligne 1-based, sans fin de ligne. */
    public String line(int lineNumber) {
        int start = lineStarts[lineNumber - 1];
        int end = lineNumber < lineStarts.length ? lineStarts[lineNumber] - 1 : content.length();
        if (end > start && content.charAt(end - 1) == '\r') {
            end--;
        }
        return content.substring(start, Math.max(start, end));
    }

    public String snippet(int lineNumber) {
        String line = line(lineNumber).strip();
        return line.length() > MAX_SNIPPET_LENGTH ? line.substring(0, MAX_SNIPPET_LENGTH) + "..." : line;
    }

    public boolean isCommentLine(int lineNumber, List<String> commentPrefixes) {
        String trimmed = line(lineNumber).stripLeading();
        return commentPrefixes.stream().anyMatch(trimmed::startsWith)
                || commentPrefixes.contains(BLOCK_OPEN) && blockLines().get(lineNumber);
    }

    /**
     * Lignes des blocs {@code <# ... #>} ouverts en début de ligne, délimiteurs compris : l'aide intégrée de
     * PowerShell, dont les exemples (ConvertTo-SecureString 'Password123!' -AsPlainText) ne sont pas du code.
     */
    private BitSet blockLines() {
        if (blockLines == null) {
            BitSet lines = new BitSet();
            boolean open = false;
            for (int n = 1; n <= lineCount(); n++) {
                String text = line(n);
                int from = 0;
                if (!open && text.stripLeading().startsWith(BLOCK_OPEN)) {
                    open = true;
                    from = text.indexOf(BLOCK_OPEN) + BLOCK_OPEN.length();
                }
                if (open) {
                    lines.set(n);
                    open = text.indexOf(BLOCK_CLOSE, from) < 0;
                }
            }
            blockLines = lines;
        }
        return blockLines;
    }
}
