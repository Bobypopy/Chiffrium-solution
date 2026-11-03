package com.chiffrium.infrastructure.process;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

/**
 * Exécute un processus externe sans passer par un shell (arguments transmis tels quels : pas
 * d'injection possible), relaie sa sortie dans les logs et le tue avec ses descendants s'il dépasse
 * le délai imparti.
 */
public class ProcessRunner {

    private static final Logger LOG = LoggerFactory.getLogger(ProcessRunner.class);
    private static final int MAX_CAPTURED_LINES = 200;
    private static final long READER_JOIN_MILLIS = 5_000;

    /**
     * @param exitCode   code de retour (-1 en cas de dépassement de délai)
     * @param timedOut   vrai si le processus a été tué
     * @param lastOutput dernières lignes produites (diagnostic)
     */
    public record Result(int exitCode, boolean timedOut, List<String> lastOutput) {

        public boolean succeeded() {
            return !timedOut && exitCode == 0;
        }
    }

    public Result run(List<String> command, Path workingDir, Map<String, String> extraEnv, Duration timeout,
                      String logPrefix) throws IOException {
        ProcessBuilder builder = new ProcessBuilder(command)
                .directory(workingDir.toFile())
                .redirectErrorStream(true);
        builder.environment().putAll(extraEnv);
        LOG.info("Exécution : {}", String.join(" ", command));

        Process process = builder.start();
        process.getOutputStream().close();
        List<String> tail = new ArrayList<>();
        // Le contexte de log (identifiant d'analyse) est propagé pour que la sortie aille dans le bon journal.
        Map<String, String> logContext = MDC.getCopyOfContextMap();
        Thread reader = Thread.ofVirtual().start(() -> {
            if (logContext != null) {
                MDC.setContextMap(logContext);
            }
            pump(process, logPrefix, tail);
        });
        try {
            boolean finished = process.waitFor(timeout.toMillis(), TimeUnit.MILLISECONDS);
            if (!finished) {
                LOG.warn("{} : délai de {} s dépassé, arrêt forcé", logPrefix, timeout.toSeconds());
                process.descendants().forEach(ProcessHandle::destroyForcibly);
                process.destroyForcibly();
            }
            reader.join(READER_JOIN_MILLIS);
            synchronized (tail) {
                return new Result(finished ? process.exitValue() : -1, !finished, List.copyOf(tail));
            }
        } catch (InterruptedException e) {
            process.descendants().forEach(ProcessHandle::destroyForcibly);
            process.destroyForcibly();
            Thread.currentThread().interrupt();
            throw new IOException("Exécution interrompue : " + command.get(0), e);
        }
    }

    private static void pump(Process process, String prefix, List<String> tail) {
        try (BufferedReader in = new BufferedReader(
                new InputStreamReader(process.getInputStream(), StandardCharsets.UTF_8))) {
            String line;
            while ((line = in.readLine()) != null) {
                LOG.info("[{}] {}", prefix, line);
                synchronized (tail) {
                    tail.add(line);
                    if (tail.size() > MAX_CAPTURED_LINES) {
                        tail.remove(0);
                    }
                }
            }
        } catch (IOException e) {
            LOG.debug("Lecture de la sortie de {} interrompue", prefix, e);
        }
    }
}
