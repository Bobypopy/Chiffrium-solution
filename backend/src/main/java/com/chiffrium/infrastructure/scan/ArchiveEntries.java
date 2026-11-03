package com.chiffrium.infrastructure.scan;

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Locale;
import java.util.function.Consumer;
import java.util.zip.GZIPInputStream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

/**
 * Lit en mémoire les fichiers d'une archive versionnée (famille zip, tar, tar.gz) sans jamais rien extraire sur le
 * disque. Garde-fous contre les archives piégées : taille par entrée, nombre d'entrées et volume total
 * décompressé bornés. Les archives imbriquées ne sont pas ouvertes.
 */
public final class ArchiveEntries {

    /** Taille maximale d'une entrée lue (au-delà, elle est ignorée). */
    public static final int MAX_ENTRY_BYTES = 2 * 1024 * 1024;
    static final int MAX_ENTRIES = 10_000;
    static final long MAX_TOTAL_BYTES = 64L * 1024 * 1024;
    /** Séparateur entre l'archive et le fichier qu'elle contient, comme dans les URL "jar:". */
    public static final String SEPARATOR = "!/";
    private static final int TAR_BLOCK = 512;
    private static final int TAR_NAME_LENGTH = 100;
    private static final int TAR_SIZE_OFFSET = 124;
    private static final int TAR_SIZE_LENGTH = 12;
    private static final int TAR_TYPE_OFFSET = 156;
    private static final int TAR_MAGIC_OFFSET = 257;
    private static final int TAR_PREFIX_OFFSET = 345;
    private static final int TAR_PREFIX_LENGTH = 155;
    private static final char TAR_LONG_NAME = 'L';

    private ArchiveEntries() {
    }

    /** Fichier d'une archive : chemin dans l'archive et contenu. */
    public record Entry(String path, byte[] content) {
    }

    /**
     * Parcourt les fichiers de l'archive (dossiers et liens exclus), dans l'ordre de l'archive.
     *
     * @throws IOException archive illisible ou tronquée
     */
    public static void forEach(Path archive, Consumer<Entry> consumer) throws IOException {
        String name = archive.getFileName().toString().toLowerCase(Locale.ROOT);
        try (InputStream in = new BufferedInputStream(Files.newInputStream(archive))) {
            Budget budget = new Budget();
            if (FileClassifier.isTarArchive(name)) {
                readTar(name.endsWith("gz") ? new GZIPInputStream(in) : in, budget, consumer);
            } else {
                readZip(new ZipInputStream(in), budget, consumer);
            }
        }
    }

    /** Nombre d'entrées et volume décompressé restants pour une archive. */
    private static final class Budget {
        private int entries;
        private long bytes;

        boolean accept(long size) {
            entries++;
            bytes += size;
            return entries <= MAX_ENTRIES && bytes <= MAX_TOTAL_BYTES;
        }

        boolean exhausted() {
            return entries >= MAX_ENTRIES || bytes >= MAX_TOTAL_BYTES;
        }
    }

    private static void readZip(ZipInputStream zip, Budget budget, Consumer<Entry> consumer) throws IOException {
        ZipEntry entry;
        while (!budget.exhausted() && (entry = zip.getNextEntry()) != null) {
            if (entry.isDirectory()) {
                continue;
            }
            // La taille déclarée peut mentir : la lecture elle-même est bornée.
            byte[] content = readAtMost(zip, MAX_ENTRY_BYTES);
            if (content != null && budget.accept(content.length)) {
                consumer.accept(new Entry(entry.getName(), content));
            }
        }
    }

    private static void readTar(InputStream tar, Budget budget, Consumer<Entry> consumer) throws IOException {
        String longName = null;
        while (!budget.exhausted()) {
            byte[] header = tar.readNBytes(TAR_BLOCK);
            if (header.length < TAR_BLOCK || isZero(header)) {
                return;
            }
            long size = octal(header, TAR_SIZE_OFFSET, TAR_SIZE_LENGTH);
            if (size < 0) {
                return; // taille illisible : impossible de retrouver l'entrée suivante
            }
            long padded = (size + TAR_BLOCK - 1) / TAR_BLOCK * TAR_BLOCK;
            char type = (char) header[TAR_TYPE_OFFSET];
            if (type == TAR_LONG_NAME && size <= MAX_ENTRY_BYTES) {
                longName = text(tar.readNBytes((int) size), 0, (int) size);
                tar.skipNBytes(padded - size);
                continue;
            }
            String path = longName != null ? longName : name(header);
            longName = null;
            boolean regularFile = type == '0' || type == '\0';
            if (regularFile && size <= MAX_ENTRY_BYTES && budget.accept(size)) {
                byte[] content = tar.readNBytes((int) size);
                tar.skipNBytes(padded - size);
                consumer.accept(new Entry(path, content));
            } else {
                tar.skipNBytes(padded);
            }
        }
    }

    private static String name(byte[] header) {
        String name = text(header, 0, TAR_NAME_LENGTH);
        boolean ustar = text(header, TAR_MAGIC_OFFSET, 5).equals("ustar");
        String prefix = ustar ? text(header, TAR_PREFIX_OFFSET, TAR_PREFIX_LENGTH) : "";
        return prefix.isEmpty() ? name : prefix + "/" + name;
    }

    private static String text(byte[] bytes, int offset, int length) {
        int end = offset;
        while (end < offset + length && end < bytes.length && bytes[end] != 0) {
            end++;
        }
        return new String(bytes, offset, end - offset, StandardCharsets.UTF_8);
    }

    /** Champ numérique octal d'un en-tête tar ; -1 si illisible (dont le format binaire des très grosses entrées). */
    private static long octal(byte[] header, int offset, int length) {
        String digits = text(header, offset, length).trim();
        try {
            return digits.isEmpty() ? 0 : Long.parseLong(digits, 8);
        } catch (NumberFormatException e) {
            return -1;
        }
    }

    private static boolean isZero(byte[] block) {
        for (byte b : block) {
            if (b != 0) {
                return false;
            }
        }
        return true;
    }

    /** Lit l'entrée courante jusqu'à {@code max} octets ; null si elle est plus grande. */
    private static byte[] readAtMost(InputStream in, int max) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buffer = new byte[8192];
        int read;
        while ((read = in.read(buffer)) > 0) {
            if (out.size() + read > max) {
                return null;
            }
            out.write(buffer, 0, read);
        }
        return out.toByteArray();
    }
}
