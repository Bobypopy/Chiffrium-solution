package com.chiffrium.infrastructure.audit;

import com.chiffrium.application.port.AuditSink;
import com.chiffrium.domain.security.AuditEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.Clock;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.List;

/**
 * Archivage dans un dossier (idéalement un montage WORM, un partage sauvegardé ou collecté par un SIEM) :
 * une ligne JSON par entrée, un fichier par jour ({@code audit-AAAA-MM-JJ.jsonl}), en ajout seul.
 */
public final class DirectoryAuditSink implements AuditSink {

    private static final String PREFIX = "audit-";
    private static final String SUFFIX = ".jsonl";

    private final Path directory;
    private final ObjectMapper mapper;
    private final Clock clock;

    public DirectoryAuditSink(Path directory, ObjectMapper mapper, Clock clock) {
        this.directory = directory;
        this.mapper = mapper;
        this.clock = clock;
    }

    @Override
    public String name() {
        return "dossier " + directory;
    }

    @Override
    public void publish(List<AuditEvent> events) {
        StringBuilder lines = new StringBuilder();
        for (AuditEvent event : events) {
            try {
                lines.append(mapper.writeValueAsString(event)).append('\n');
            } catch (JsonProcessingException e) {
                throw new IllegalStateException("Entrée d'audit non sérialisable", e);
            }
        }
        Path file = directory.resolve(PREFIX + LocalDate.now(clock.withZone(ZoneOffset.UTC)) + SUFFIX);
        try {
            Files.createDirectories(directory);
            Files.writeString(file, lines, StandardCharsets.UTF_8, StandardOpenOption.CREATE, StandardOpenOption.APPEND);
        } catch (IOException e) {
            throw new UncheckedIOException("Écriture impossible : " + file, e);
        }
    }
}
