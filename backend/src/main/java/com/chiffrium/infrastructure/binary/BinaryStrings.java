package com.chiffrium.infrastructure.binary;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * Chaînes lisibles d'un fichier compilé : constantes du bytecode Java (lues dans la table des constantes, sans
 * octet parasite), suites ASCII et UTF-16 (chaînes .NET) des autres binaires, comme la commande {@code strings}.
 */
final class BinaryStrings {

    static final int MIN_LENGTH = 3;
    /** Au-delà, la chaîne n'est pas un nom d'algorithme ou un symbole : inutile de la garder. */
    static final int MAX_LENGTH = 256;
    private static final int CLASS_MAGIC = 0xCAFEBABE;

    private BinaryStrings() {
    }

    /** Constantes UTF-8 d'un fichier .class ; à défaut de format reconnu, les suites lisibles. */
    static List<String> classConstants(byte[] content) {
        try {
            return parseConstantPool(content);
        } catch (IndexOutOfBoundsException | IllegalStateException e) {
            return extract(content);
        }
    }

    private static List<String> parseConstantPool(byte[] b) {
        if (b.length < 10 || u4(b, 0) != CLASS_MAGIC) {
            throw new IllegalStateException("pas un fichier .class");
        }
        int count = u2(b, 8);
        int offset = 10;
        List<String> strings = new ArrayList<>();
        for (int index = 1; index < count; index++) {
            int tag = b[offset] & 0xFF;
            offset++;
            switch (tag) {
                case 1 -> {
                    int length = u2(b, offset);
                    if (length <= MAX_LENGTH) {
                        strings.add(new String(b, offset + 2, length, StandardCharsets.UTF_8));
                    }
                    offset += 2 + length;
                }
                case 3, 4, 9, 10, 11, 12, 17, 18 -> offset += 4;
                case 5, 6 -> {
                    offset += 8;
                    index++;
                }
                case 7, 8, 16, 19, 20 -> offset += 2;
                case 15 -> offset += 3;
                default -> throw new IllegalStateException("étiquette de constante inconnue " + tag);
            }
        }
        return strings;
    }

    /** Suites d'au moins {@link #MIN_LENGTH} caractères imprimables, en ASCII et en UTF-16 petit-boutiste. */
    static List<String> extract(byte[] content) {
        List<String> strings = new ArrayList<>();
        StringBuilder run = new StringBuilder();
        for (byte b : content) {
            if (printable(b & 0xFF)) {
                run.append((char) (b & 0xFF));
            } else {
                flush(run, strings);
            }
        }
        flush(run, strings);
        // UTF-16LE (chaînes utilisateur .NET) : caractère imprimable puis octet nul, aux deux alignements.
        for (int start = 0; start < 2; start++) {
            for (int i = start; i + 1 < content.length; i += 2) {
                if (printable(content[i] & 0xFF) && content[i + 1] == 0) {
                    run.append((char) (content[i] & 0xFF));
                } else {
                    flush(run, strings);
                }
            }
            flush(run, strings);
        }
        return strings;
    }

    private static void flush(StringBuilder run, List<String> strings) {
        if (run.length() >= MIN_LENGTH && run.length() <= MAX_LENGTH) {
            strings.add(run.toString());
        }
        run.setLength(0);
    }

    private static boolean printable(int c) {
        return c >= 0x20 && c < 0x7F;
    }

    private static int u2(byte[] b, int offset) {
        return ((b[offset] & 0xFF) << 8) | (b[offset + 1] & 0xFF);
    }

    private static int u4(byte[] b, int offset) {
        return (u2(b, offset) << 16) | u2(b, offset + 2);
    }
}
