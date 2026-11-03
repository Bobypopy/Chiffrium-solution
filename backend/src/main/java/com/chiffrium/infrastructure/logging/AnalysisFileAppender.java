package com.chiffrium.infrastructure.logging;

import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.AppenderBase;
import ch.qos.logback.core.encoder.Encoder;
import com.chiffrium.application.AnalysisService;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.regex.Pattern;

/**
 * Écrit chaque événement émis dans le contexte d'une analyse dans {@code <DATA_DIR>/analyses/<id>/analysis.log}.
 * Le fichier est ouvert puis refermé à chaque écriture : aucun descripteur n'est conservé, ce qui permet de
 * supprimer une analyse à tout moment (y compris sous Windows) sans dépendre d'un délai de fermeture.
 */
public final class AnalysisFileAppender extends AppenderBase<ILoggingEvent> {

    private static final Pattern SAFE_ID = Pattern.compile("[0-9a-f-]{36}");
    private static final String DEFAULT_DATA_DIR = "./data";

    private Encoder<ILoggingEvent> encoder;

    public void setEncoder(Encoder<ILoggingEvent> encoder) {
        this.encoder = encoder;
    }

    @Override
    public void start() {
        if (encoder == null) {
            addError("Aucun encodeur configuré pour " + getName());
            return;
        }
        super.start();
    }

    @Override
    protected synchronized void append(ILoggingEvent event) {
        String id = event.getMDCPropertyMap().get(AnalysisService.MDC_ANALYSIS_ID);
        if (id == null || !SAFE_ID.matcher(id).matches()) {
            return;
        }
        String dataDir = getContext().getProperty(LoggingSetup.DATA_DIR_PROPERTY);
        if (dataDir == null) {
            dataDir = System.getenv().getOrDefault(LoggingSetup.DATA_DIR_PROPERTY, DEFAULT_DATA_DIR);
        }
        Path file = Path.of(dataDir, "analyses", id, "analysis.log");
        try {
            Files.createDirectories(file.getParent());
            Files.write(file, encoder.encode(event), StandardOpenOption.CREATE, StandardOpenOption.APPEND);
        } catch (IOException e) {
            addError("Écriture impossible dans " + file, e);
        }
    }
}
