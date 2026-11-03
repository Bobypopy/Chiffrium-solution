package com.chiffrium.infrastructure.npm;

import com.chiffrium.TestSupport;
import com.chiffrium.infrastructure.process.ProcessRunner;
import com.chiffrium.infrastructure.scan.FileSystemProjectScanner;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class NpmLockfileGeneratorTest {

    private static final long MAX_FILE_BYTES = 1_000_000;
    private static final String REGISTRY = "https://registry.example.test/";

    /** Enregistre les commandes au lieu de lancer npm. */
    static final class RecordingRunner extends ProcessRunner {
        final List<Path> directories = new ArrayList<>();
        final List<List<String>> commands = new ArrayList<>();

        @Override
        public Result run(List<String> command, Path workingDir, Map<String, String> extraEnv, Duration timeout,
                          String logPrefix) {
            commands.add(command);
            directories.add(workingDir);
            return new Result(0, false, List.of());
        }
    }

    @Test
    void generatesOnlyMissingLockfilesWithoutRunningScripts(@TempDir Path root) {
        TestSupport.write(root, "web/package.json", "{}");
        TestSupport.write(root, "api/package.json", "{}");
        TestSupport.write(root, "api/yarn.lock", "");
        RecordingRunner runner = new RecordingRunner();
        NpmLockfileGenerator generator = new NpmLockfileGenerator(runner, "npm", REGISTRY, Duration.ofSeconds(1), () -> true);

        List<String> notes = generator.prepare(root, new FileSystemProjectScanner(MAX_FILE_BYTES).scan(root));

        assertThat(runner.directories).containsExactly(root.resolve("web"));
        assertThat(runner.commands.get(0)).contains("--package-lock-only", "--ignore-scripts", "--registry=" + REGISTRY);
        assertThat(notes).singleElement().asString().contains("web");
    }

    @Test
    void doesNothingWhenDisabled(@TempDir Path root) {
        TestSupport.write(root, "package.json", "{}");
        RecordingRunner runner = new RecordingRunner();
        new NpmLockfileGenerator(runner, "npm", REGISTRY, Duration.ofSeconds(1), () -> false)
                .prepare(root, new FileSystemProjectScanner(MAX_FILE_BYTES).scan(root));
        assertThat(runner.commands).isEmpty();
    }
}
