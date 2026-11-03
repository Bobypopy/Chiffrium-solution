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
            // Composants web : le script est du JavaScript ou du TypeScript au milieu du gabarit.
            Map.entry("vue", Language.JAVASCRIPT), Map.entry("svelte", Language.JAVASCRIPT),
            Map.entry("astro", Language.JAVASCRIPT),
            // Pages serveur et gabarits : le code du langage hôte.
            Map.entry("jsp", Language.JAVA), Map.entry("cshtml", Language.CSHARP), Map.entry("razor", Language.CSHARP),
            Map.entry("erb", Language.RUBY), Map.entry("gradle", Language.GROOVY),
            Map.entry("pyi", Language.PYTHON), Map.entry("ipynb", Language.PYTHON),
            Map.entry("vb", Language.VBNET), Map.entry("fs", Language.FSHARP), Map.entry("fsx", Language.FSHARP),
            Map.entry("fsi", Language.FSHARP), Map.entry("erl", Language.ERLANG), Map.entry("hrl", Language.ERLANG),
            Map.entry("cbl", Language.COBOL), Map.entry("cob", Language.COBOL), Map.entry("cpy", Language.COBOL),
            Map.entry("cobol", Language.COBOL), Map.entry("abap", Language.ABAP), Map.entry("lua", Language.LUA),
            Map.entry("sol", Language.SOLIDITY), Map.entry("cls", Language.APEX), Map.entry("trigger", Language.APEX),
            Map.entry("hs", Language.HASKELL), Map.entry("lhs", Language.HASKELL), Map.entry("r", Language.R),
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
            Map.entry("xml", Language.CONFIG), Map.entry("plist", Language.CONFIG),Map.entry("security", Language.CONFIG), Map.entry("tf", Language.CONFIG),
            Map.entry("tfvars", Language.CONFIG), Map.entry("sh", Language.CONFIG), Map.entry("bash", Language.CONFIG),
            Map.entry("ps1", Language.POWERSHELL), Map.entry("psm1", Language.POWERSHELL),
            Map.entry("psd1", Language.POWERSHELL),
            Map.entry("npmrc", Language.CONFIG), Map.entry("pypirc", Language.CONFIG),
            Map.entry("zsh", Language.CONFIG), Map.entry("bat", Language.CONFIG), Map.entry("cmd", Language.CONFIG),
            Map.entry("hcl", Language.CONFIG), Map.entry("bicep", Language.CONFIG),
            Map.entry("tpl", Language.CONFIG), Map.entry("j2", Language.CONFIG), Map.entry("nix", Language.CONFIG),
            // CloudFormation, modèles ARM, configurations applicatives (les fichiers de verrouillage sont écartés).
            Map.entry("json", Language.CONFIG));

    /** Listes de dépendances générées : volumineuses, sans configuration cryptographique, lues comme données. */
    private static final Set<String> LOCK_FILES = Set.of("package-lock.json", "npm-shrinkwrap.json",
            "composer.lock", "packages.lock.json");

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

    /**
     * Code compilé (bytecode Java, assemblages .NET, bibliothèques et exécutables natifs) : on y lit les chaînes
     * et les symboles qui nomment un algorithme ("DES/ECB/PKCS5Padding", EVP_des_ede3_cbc, MD5CryptoServiceProvider).
     */
    private static final Set<String> BINARY_EXTENSIONS = Set.of("class", "dll", "exe", "so", "dylib", "a", "o",
            "lib", "dex", "node", "pyd", "pyc");

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
        if (LOCK_FILES.contains(lower)) {
            return Optional.empty();
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

    /**
     * Début d'un exécutable natif (ELF, Mach-O, PE) : les binaires Go ou Rust n'ont souvent pas d'extension sous
     * Linux et macOS, on les reconnaît à leurs premiers octets.
     */
    public static boolean isExecutable(byte[] head) {
        if (head.length < 4) {
            return false;
        }
        int magic = ((head[0] & 0xFF) << 24) | ((head[1] & 0xFF) << 16) | ((head[2] & 0xFF) << 8) | (head[3] & 0xFF);
        return magic == 0x7F454C46 || magic == 0xFEEDFACE || magic == 0xFEEDFACF || magic == 0xCEFAEDFE
                || magic == 0xCFFAEDFE || (head[0] == 'M' && head[1] == 'Z');
    }

    /** Nom sans extension (binaire Go "server", script "deploy") : seul son contenu dit ce qu'il est. */
    public static boolean hasNoExtension(String fileName) {
        String name = fileName.substring(fileName.lastIndexOf('/') + 1);
        return name.indexOf('.') < 0;
    }

    public static boolean isBinary(String fileName) {
        String lower = fileName.toLowerCase(Locale.ROOT);
        return extension(lower).map(BINARY_EXTENSIONS::contains).orElse(false) || lower.matches(".*\\.so\\.\\d.*");
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
