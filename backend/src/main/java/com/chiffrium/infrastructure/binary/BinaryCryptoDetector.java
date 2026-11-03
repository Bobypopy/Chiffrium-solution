package com.chiffrium.infrastructure.binary;

import com.chiffrium.application.port.CryptoDetector;
import com.chiffrium.application.port.ProjectScanner.ScannedFile;
import com.chiffrium.domain.asset.AssetFactory;
import com.chiffrium.domain.model.AlgorithmSpec;
import com.chiffrium.domain.model.CryptoAsset;
import com.chiffrium.domain.model.CryptoFunction;
import com.chiffrium.domain.model.DetectionSource;
import com.chiffrium.domain.model.Occurrence;
import com.chiffrium.infrastructure.scan.ArchiveEntries;
import com.chiffrium.infrastructure.scan.FileClassifier;
import com.chiffrium.infrastructure.scan.FileFailures;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Matcher;

/**
 * Code compilé : bytecode Java ({@code .class}, y compris dans les jar, war et apk), assemblages .NET,
 * bibliothèques et exécutables natifs. Sans décompiler, on lit les chaînes et les symboles qui nomment un
 * algorithme ({@code "DES/ECB/PKCS5Padding"}, {@code EVP_des_ede3_cbc}, {@code MD5CryptoServiceProvider}) :
 * c'est ce que l'application compilée appellera. Un binaire dont le source est aussi dans le dépôt donne les
 * mêmes algorithmes, à l'emplacement du binaire ; une bibliothèque livrée sans source n'est vue que par là.
 */
public final class BinaryCryptoDetector implements CryptoDetector {

    private static final int MAX_SNIPPET = 200;

    private final AssetFactory assetFactory;
    private final List<BinarySignatures.Signature> signatures;

    public BinaryCryptoDetector(AssetFactory assetFactory, List<BinarySignatures.Signature> signatures) {
        this.assetFactory = assetFactory;
        this.signatures = List.copyOf(signatures);
    }

    @Override
    public String name() {
        return "code compilé";
    }

    @Override
    public DetectionResult detect(DetectionContext context) {
        List<CryptoAsset> assets = new ArrayList<>();
        FileFailures failures = new FileFailures(name());
        for (ScannedFile file : context.scan().files()) {
            Path path = context.projectRoot().resolve(file.path());
            try {
                if (FileClassifier.isBinary(file.path())) {
                    assets.addAll(scan(file.path(), Files.readAllBytes(path)));
                } else if (file.language() == null && !file.material() && FileClassifier.hasNoExtension(file.path())) {
                    byte[] content = Files.readAllBytes(path);
                    if (FileClassifier.isExecutable(content)) {
                        assets.addAll(scan(file.path(), content));
                    }
                } else if (FileClassifier.isArchive(file.path())) {
                    ArchiveEntries.forEach(path, entry -> {
                        if (FileClassifier.isBinary(entry.path())) {
                            assets.addAll(scan(file.path() + ArchiveEntries.SEPARATOR + entry.path(), entry.content()));
                        }
                    });
                }
            } catch (IOException | RuntimeException | StackOverflowError e) {
                failures.record(file.path(), e);
            }
        }
        return new DetectionResult(assets, List.of(), failures.warnings());
    }

    /** Un actif par algorithme et par fichier, quel que soit le nombre de chaînes qui le nomment. */
    List<CryptoAsset> scan(String file, byte[] content) {
        List<CryptoAsset> assets = new ArrayList<>();
        Set<String> seen = new HashSet<>();
        boolean classFile = file.toLowerCase(Locale.ROOT).endsWith(".class");
        for (String text : classFile ? BinaryStrings.classConstants(content) : BinaryStrings.extract(content)) {
            for (BinarySignatures.Signature signature : signatures) {
                if (!signature.appliesTo(file)) {
                    continue;
                }
                Matcher matcher = signature.pattern().matcher(text);
                if (!matcher.find()) {
                    continue;
                }
                String raw = signature.mapped(matcher.group("name"));
                AlgorithmSpec spec = assetFactory.normalizer().normalize(raw);
                if (spec.isRecognized() && seen.add(spec.displayName())) {
                    Set<CryptoFunction> functions = signature.functions().isEmpty()
                            ? Set.of() : EnumSet.copyOf(signature.functions());
                    Occurrence occurrence = new Occurrence(file, null, null, null,
                            text.length() > MAX_SNIPPET ? text.substring(0, MAX_SNIPPET) + "..." : text, null,
                            DetectionSource.BINARY, "binary." + signature.id(), functions);
                    assets.add(assetFactory.fromSpec(spec, occurrence, functions, DetectionSource.BINARY, null));
                }
                break;
            }
        }
        return assets;
    }
}
