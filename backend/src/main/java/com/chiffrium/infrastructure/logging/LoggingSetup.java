package com.chiffrium.infrastructure.logging;

import ch.qos.logback.classic.LoggerContext;
import org.slf4j.ILoggerFactory;
import org.slf4j.LoggerFactory;

import java.nio.file.Path;

/**
 * Transmet à logback le dossier de données effectif, pour que les journaux d'analyse soient écrits au
 * bon endroit même quand DATA_DIR ne vient pas d'une variable d'environnement (tests, CLI).
 */
public final class LoggingSetup {

    static final String DATA_DIR_PROPERTY = "DATA_DIR";

    private LoggingSetup() {
    }

    public static void useDataDir(Path dataDir) {
        ILoggerFactory factory = LoggerFactory.getILoggerFactory();
        if (factory instanceof LoggerContext context) {
            context.putProperty(DATA_DIR_PROPERTY, dataDir.toAbsolutePath().toString());
        }
    }
}
