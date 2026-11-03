package com.chiffrium.infrastructure.scan;

import com.chiffrium.domain.model.Language;

import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * Classe les fichiers par langage (extension), repère les manifestes de projet et les fichiers
 * de matériel cryptographique. Tables centralisées ici pour éviter toute duplication.
 */
public final class FileClassifier {

    private static final Map<String, Language> EXTENSIONS = Map.ofEntries(
            Map.entry("java", Language.JAVA),
            Map.entry("kt", Language.KOTLIN), Map.entry("kts", Language.KOTLIN),
            Map.entry("scala", Language.SCALA), Map.entry("sc", Language.SCALA),
            Map.entry("groovy", Language.GROOVY),
            Map.entry("py", Language.PYTHON), Map.entry("pyw", Language.PYTHON),
            Map.entry("js", Language.JAVASCRIPT), Map.entry("mjs", Language.JAVASCRIPT),
            Map.entry("cjs", Language.JAVASCRIPT), Map.entry("jsx", Language.JAVASCRIPT),
            Map.entry("ts", Language.TYPESCRIPT), Map.entry("tsx", Language.TYPESCRIPT),
            Map.entry("mts", Language.TYPESCRIPT), Map.entry("cts", Language.TYPESCRIPT),
            Map.entry("go", Language.GO),
            Map.entry("cs", Language.CSHARP),
            Map.entry("c", Language.C), Map.entry("h", Language.C),
            Map.entry("cpp", Language.CPP), Map.entry("cc", Language.CPP), Map.entry("cxx", Language.CPP),
            Map.entry("hpp", Language.CPP), Map.entry("hh", Language.CPP), Map.entry("hxx", Language.CPP),
            Map.entry("php", Language.PHP),
            Map.entry("rb", Language.RUBY),
            Map.entry("rs", Language.RUST),
            Map.entry("swift", Language.SWIFT),
            Map.entry("dart", Language.DART),
            Map.entry("ex", Language.ELIXIR), Map.entry("exs", Language.ELIXIR),
            Map.entry("pl", Language.PERL), Map.entry("pm", Language.PERL),
            Map.entry("m", Language.OBJC), Map.entry("mm", Language.OBJC),
            Map.entry("sql", Language.SQL),
            Map.entry("conf", Language.CONFIG), Map.entry("cnf", Language.CONFIG),
            Map.entry("properties", Language.CONFIG), Map.entry("yml", Language.CONFIG),
            Map.entry("yaml", Language.CONFIG), Map.entry("ini", Language.CONFIG),
            Map.entry("toml", Language.CONFIG), Map.entry("env", Language.CONFIG), Map.entry("cfg", Language.CONFIG),
            Map.entry("xml", Language.CONFIG), Map.entry("security", Language.CONFIG), Map.entry("tf", Language.CONFIG),
            Map.entry("tfvars", Language.CONFIG), Map.entry("sh", Language.CONFIG), Map.entry("bash", Language.CONFIG),
            Map.entry("ps1", Language.CONFIG), Map.entry("npmrc", Language.CONFIG), Map.entry("pypirc", Language.CONFIG));

    /** Fichiers de configuration sans extension significative. */
    private static final Map<String, Language> FILE_NAMES = Map.of(
            "dockerfile", Language.CONFIG, "makefile", Language.CONFIG, "sshd_config", Language.CONFIG,
            "ssh_config", Language.CONFIG, "appsettings.json", Language.CONFIG,
            "appsettings.development.json", Language.CONFIG, "appsettings.production.json", Language.CONFIG);

    /** Préfixe des fichiers d'environnement (.env, .env.local...). */
    private static final String ENV_FILE_PREFIX = ".env";

    private static final Set<String> MATERIAL_EXTENSIONS = Set.of(
            "pem", "crt", "cer", "der", "key", "pub", "p12", "pfx", "jks", "keystore", "bks", "p7b", "p7c",
            "csr", "ppk", "asc", "gpg");

    private static final Set<String> MATERIAL_FILE_NAMES = Set.of(
            "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "id_rsa.pub", "id_ecdsa.pub", "id_ed25519.pub");

    /**
     * Fichiers de données lus seulement pour y chercher des clés et des secrets (pas de règles d'algorithmes) :
     * JSON de compte de service, JWK, état Terraform, notebook, kubeconfig, notes.
     */
    private static final Set<String> DATA_EXTENSIONS = Set.of("json", "jwk", "jwks", "ipynb", "tfstate", "txt");
    private static final Set<String> DATA_FILE_NAMES = Set.of("kubeconfig");
    private static final String TERRAFORM_STATE_BACKUP = ".tfstate.backup";

    /** Archives versionnées, ouvertes en mémoire pour y chercher clés et secrets (voir {@link ArchiveEntries}). */
    private static final Set<String> ZIP_EXTENSIONS = Set.of("zip", "jar", "war", "ear", "aar", "apk", "whl", "nupkg");
    private static final List<String> TAR_SUFFIXES = List.of(".tar", ".tar.gz", ".tgz");

    private static final Set<String> MANIFESTS = Set.of(
            "pom.xml", "build.gradle", "build.gradle.kts", "settings.gradle", "settings.gradle.kts", "build.sbt",
            "package.json", "requirements.txt", "pyproject.toml", "setup.py", "pipfile", "go.mod",
            "packages.config", "cmakelists.txt", "conanfile.txt", "conanfile.py", "vcpkg.json", "composer.json",
            "gemfile", "cargo.toml", "package.swift", "podfile", "pubspec.yaml", "mix.exs", "cpanfile");

    private static final Set<String> MANIFEST_EXTENSIONS = Set.of("csproj", "sln", "fsproj", "vbproj");

    /** Dossiers jamais parcourus : dépendances, sorties de build, environnements virtuels, métadonnées. */
    private static final Set<String> IGNORED_DIRECTORIES = Set.of(
            ".git", ".hg", ".svn", "node_modules", "bower_components", "target", "build", "dist", "out", "obj",
            "vendor", "venv", ".venv", "env", "__pycache__", ".idea", ".vscode", ".gradle", ".mvn", ".tox",
            ".next", ".nuxt", "coverage", ".terraform", "pods", ".cache", ".pytest_cache", ".mypy_cache");

    private FileClassifier() {
    }

    public static Optional<Language> languageOf(String fileName) {
        String lower = fileName.toLowerCase(Locale.ROOT);
        if (FILE_NAMES.containsKey(lower)) {
            return Optional.of(FILE_NAMES.get(lower));
        }
        if (lower.startsWith(ENV_FILE_PREFIX)) {
            return Optional.of(Language.CONFIG);
        }
        return extension(fileName).map(EXTENSIONS::get);
    }

    public static boolean isMaterial(String fileName) {
        String lower = fileName.toLowerCase(Locale.ROOT);
        return MATERIAL_FILE_NAMES.contains(lower) || extension(lower).map(MATERIAL_EXTENSIONS::contains).orElse(false);
    }

    public static boolean isData(String fileName) {
        String lower = fileName.toLowerCase(Locale.ROOT);
        return DATA_FILE_NAMES.contains(lower) || lower.endsWith(TERRAFORM_STATE_BACKUP)
                || extension(lower).map(DATA_EXTENSIONS::contains).orElse(false);
    }

    /** Fichier lu par les détecteurs : code ou configuration, matériel cryptographique, ou données. */
    public static boolean isScanned(String fileName) {
        return languageOf(fileName).isPresent() || isMaterial(fileName) || isData(fileName);
    }

    public static boolean isArchive(String fileName) {
        String lower = fileName.toLowerCase(Locale.ROOT);
        return isTarArchive(lower) || extension(lower).map(ZIP_EXTENSIONS::contains).orElse(false);
    }

    static boolean isTarArchive(String fileName) {
        String lower = fileName.toLowerCase(Locale.ROOT);
        return TAR_SUFFIXES.stream().anyMatch(lower::endsWith);
    }

    public static boolean isManifest(String fileName) {
        String lower = fileName.toLowerCase(Locale.ROOT);
        return MANIFESTS.contains(lower) || extension(lower).map(MANIFEST_EXTENSIONS::contains).orElse(false);
    }

    public static boolean isIgnoredDirectory(String directoryName) {
        return IGNORED_DIRECTORIES.contains(directoryName.toLowerCase(Locale.ROOT));
    }

    public static Optional<String> extension(String fileName) {
        int dot = fileName.lastIndexOf('.');
        if (dot < 0 || dot == fileName.length() - 1) {
            return Optional.empty();
        }
        return Optional.of(fileName.substring(dot + 1).toLowerCase(Locale.ROOT));
    }
}
