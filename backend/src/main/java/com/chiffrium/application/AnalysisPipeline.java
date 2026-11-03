package com.chiffrium.application;

import com.chiffrium.application.graph.CallGraphBuilder;
import com.chiffrium.application.port.AnalysisRepository;
import com.chiffrium.application.port.CallEdgeExtractor;
import com.chiffrium.application.port.CatalogRepository;
import com.chiffrium.application.port.CbomWriter;
import com.chiffrium.application.port.ReportExporter;
import com.chiffrium.application.port.CryptoDetector;
import com.chiffrium.application.port.CryptoDetector.DetectionContext;
import com.chiffrium.application.port.CryptoDetector.DetectionResult;
import com.chiffrium.application.port.CryptoDetector.FileFlow;
import com.chiffrium.application.port.HistoryScanner;
import com.chiffrium.application.port.LibraryReader;
import com.chiffrium.application.port.ProjectScanner;
import com.chiffrium.application.port.ProjectScanner.ScanResult;
import com.chiffrium.application.port.SbomGenerator;
import com.chiffrium.application.port.SourcePreparer;
import com.chiffrium.application.port.SbomGenerator.SbomResult;
import com.chiffrium.application.port.SourceFetcher;
import com.chiffrium.application.port.SourceFetcher.FetchedSource;
import com.chiffrium.application.port.VulnerabilityScanner;
import com.chiffrium.domain.asset.AssetFactory;
import com.chiffrium.domain.asset.AssetMerger;
import com.chiffrium.domain.model.AnalysisJob;
import com.chiffrium.domain.model.AnalysisReport;
import com.chiffrium.domain.model.AnalysisRequest;
import com.chiffrium.domain.model.CallGraph;
import com.chiffrium.domain.model.CryptoAsset;
import com.chiffrium.domain.model.Language;
import com.chiffrium.domain.model.SecurityFinding;
import com.chiffrium.domain.model.Library;
import com.chiffrium.domain.model.SourceInfo;
import com.chiffrium.domain.model.StepMetric;
import com.chiffrium.domain.model.Summary;
import com.chiffrium.domain.model.Vulnerability;
import com.chiffrium.domain.policy.AlgorithmCatalog;
import com.chiffrium.domain.policy.AlgorithmNormalizer;
import com.chiffrium.domain.policy.PolicyEvaluator;
import com.chiffrium.domain.policy.SummaryCalculator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.time.Clock;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.function.Consumer;
import java.util.stream.Collectors;

/**
 * Enchaîne les étapes d'une analyse : récupération, parcours, SBOM, détections, évaluation,
 * dépendances, graphe, CBOM et rapport. Ne dépend que des ports : chaque outil externe est remplaçable.
 */
public final class AnalysisPipeline {

    private static final Logger LOG = LoggerFactory.getLogger(AnalysisPipeline.class);

    static final String STEP_FETCH = "récupération";
    static final String STEP_SCAN = "parcours";
    static final String STEP_SBOM = "cdxgen";
    static final String STEP_PREPARE_PREFIX = "préparation ";
    /** Seules les copies de travail jetables (clones) peuvent être modifiées avant analyse. */
    static final String DISPOSABLE_SOURCE_KIND = "git";
    static final String STEP_DETECT_PREFIX = "détection ";
    static final String STEP_HISTORY = "historique Git";
    static final String STEP_EVALUATE = "évaluation";
    static final String STEP_LIBRARIES = "dépendances";
    static final String STEP_VULNERABILITIES = "vulnérabilités";
    static final String STEP_GRAPH = "graphe";
    static final String STEP_CBOM = "cbom";
    static final String STEP_REPORT = "rapport";
    static final String STEP_EXPORT_PREFIX = "export ";

    private static final String RAW_OUTPUT_DIR = "raw";
    /** Sans type cdxgen : scripts PowerShell, configuration. */
    private static final Set<Language> NON_SBOM_LANGUAGES = EnumSet.of(Language.POWERSHELL, Language.CONFIG,
            Language.UNKNOWN);

    private final SourceFetcher sourceFetcher;
    private final ProjectScanner projectScanner;
    private final SbomGenerator sbomGenerator;
    private final List<SourcePreparer> preparers;
    private final DetectorProvider detectorProvider;
    private final HistoryScanner historyScanner;
    private final CallEdgeExtractor callEdgeExtractor;
    private final LibraryReader libraryReader;
    private final VulnerabilityScanner vulnerabilityScanner;
    private final CbomWriter cbomWriter;
    private final List<ReportExporter> exporters;
    private final AnalysisRepository repository;
    private final CatalogRepository catalogRepository;
    private final Clock clock;
    private final PipelineSettings settings;

    public AnalysisPipeline(SourceFetcher sourceFetcher,
                            ProjectScanner projectScanner,
                            List<SourcePreparer> preparers,
                            SbomGenerator sbomGenerator,
                            DetectorProvider detectorProvider,
                            HistoryScanner historyScanner,
                            CallEdgeExtractor callEdgeExtractor,
                            LibraryReader libraryReader,
                            VulnerabilityScanner vulnerabilityScanner,
                            CbomWriter cbomWriter,
                            List<ReportExporter> exporters,
                            AnalysisRepository repository,
                            CatalogRepository catalogRepository,
                            Clock clock,
                            PipelineSettings settings) {
        this.sourceFetcher = sourceFetcher;
        this.projectScanner = projectScanner;
        this.preparers = List.copyOf(preparers);
        this.sbomGenerator = sbomGenerator;
        this.detectorProvider = detectorProvider;
        this.historyScanner = historyScanner;
        this.callEdgeExtractor = callEdgeExtractor;
        this.libraryReader = libraryReader;
        this.vulnerabilityScanner = vulnerabilityScanner;
        this.cbomWriter = cbomWriter;
        this.exporters = List.copyOf(exporters);
        this.repository = repository;
        this.catalogRepository = catalogRepository;
        this.clock = clock;
        this.settings = settings;
    }

    /**
     * Ajoute les secrets et clés qui ne subsistent que dans l'historique Git ; un secret encore présent dans le
     * code actuel n'est signalé qu'une fois, à son emplacement actuel.
     */
    private void addHistoryFindings(FetchedSource source, Map<String, SecurityFinding> findings, StepRecorder steps) {
        HistoryScanner.HistoryResult history = steps.optional(STEP_HISTORY, () -> historyScanner.scan(source.root()),
                r -> r.findings().size() + " constat(s)", HistoryScanner.HistoryResult.empty());
        Set<String> current = findings.values().stream().map(HistoryScanner::sameSecret).collect(Collectors.toSet());
        history.findings().stream()
                .filter(f -> !current.contains(HistoryScanner.sameSecret(f)))
                .forEach(f -> findings.putIfAbsent(f.id(), f));
        steps.warn(history.warnings());
    }

    /**
     * Exécute l'analyse. Les étapes obligatoires en échec lèvent une exception ; les autres
     * produisent des avertissements dans le rapport.
     *
     * @param onStepStart appelé au début de chaque étape (suivi de progression)
     * @param onStepEnd   appelé à la fin de chaque étape
     */
    public AnalysisReport run(AnalysisJob job, Consumer<String> onStepStart, Consumer<StepMetric> onStepEnd) {
        AnalysisRequest request = job.request();
        StepRecorder steps = new StepRecorder(clock, onStepStart, onStepEnd);
        Path workspace = settings.workspaceRoot().resolve(job.id());
        Path rawDir = repository.artifactsDir(job.id()).resolve(RAW_OUTPUT_DIR);
        try {
            createDirectories(workspace);
            createDirectories(rawDir);

            FetchedSource source = steps.required(STEP_FETCH,
                    () -> sourceFetcher.fetch(request, workspace),
                    s -> s.kind() + (s.commit() == null ? "" : " @ " + s.commit()));
            ScanResult scan = steps.required(STEP_SCAN,
                    () -> projectScanner.scan(source.root()),
                    s -> s.modules().size() + " module(s), langages " + s.languages());

            prepare(source, scan, steps);
            SbomResult sbom = generateSbom(request, source, scan, rawDir, steps);

            AlgorithmCatalog catalog = catalogRepository.load();
            AssetFactory assetFactory = new AssetFactory(new AlgorithmNormalizer(catalog));
            DetectionContext context = new DetectionContext(source.root(), scan, sbom);
            List<CryptoAsset> detected = new ArrayList<>();
            List<FileFlow> fileFlows = new ArrayList<>();
            List<CallEdgeExtractor.CallEdge> codeCallEdges = new ArrayList<>();
            Map<String, SecurityFinding> findings = new LinkedHashMap<>();
            for (CryptoDetector detector : detectorProvider.detectors(assetFactory)) {
                DetectionResult result = steps.optional(STEP_DETECT_PREFIX + detector.name(),
                        () -> detector.detect(context),
                        r -> r.assets().size() + r.findings().size() + " détection(s)",
                        DetectionResult.of(List.of()));
                detected.addAll(result.assets());
                fileFlows.addAll(result.fileFlows());
                codeCallEdges.addAll(result.callEdges());
                result.findings().forEach(f -> findings.putIfAbsent(f.id(), f));
                steps.warn(result.warnings());
            }
            if (request.scanGitHistory()) {
                addHistoryFindings(source, findings, steps);
            }

            PolicyEvaluator evaluator = new PolicyEvaluator(catalog, clock);
            List<CryptoAsset> assets = steps.required(STEP_EVALUATE,
                    () -> AssetMerger.merge(detected).stream().map(evaluator::evaluate).toList(),
                    a -> a.size() + " actif(s)");

            List<Library> libraries = collectLibraries(request, sbom, steps);

            CallGraph graph = steps.optional(STEP_GRAPH, () -> {
                // Appels vus par atom (Java, Python) et appels retrouvés dans le code (tous langages, sans cdxgen).
                List<CallEdgeExtractor.CallEdge> callEdges = new ArrayList<>(callEdgeExtractor.extract(sbom));
                callEdges.addAll(codeCallEdges);
                CallGraphBuilder.Result result = new CallGraphBuilder().build(assets, fileFlows, callEdges);
                steps.warn(result.warnings());
                return result.graph();
            }, g -> g.nodes().size() + " nœud(s), " + g.edges().size() + " arête(s)", CallGraph.empty());

            SourceInfo sourceInfo = new SourceInfo(request.target(), source.kind(), source.branch(), source.commit(),
                    scan.languages(), scan.modules());

            Path cbomFile = repository.artifactsDir(job.id()).resolve(AnalysisRepository.Artifact.CBOM.fileName());
            steps.optional(STEP_CBOM, () -> {
                cbomWriter.write(cbomFile, sbom, sourceInfo, assets, libraries);
                return cbomFile;
            }, f -> f.getFileName().toString(), null);

            List<SecurityFinding> sortedFindings = findings.values().stream()
                    .sorted(SecurityFinding.BY_SEVERITY_THEN_LOCATION).toList();
            Summary summary = new SummaryCalculator().summarize(assets, libraries, sortedFindings);
            AnalysisReport report = steps.required(STEP_REPORT, () -> {
                AnalysisReport built = new AnalysisReport(AnalysisReport.CURRENT_SCHEMA_VERSION, job.id(),
                        clock.instant(), toolVersions(), sourceInfo, summary, assets, libraries, sortedFindings, graph,
                        steps.metrics(), steps.warnings());
                repository.saveReport(built);
                return built;
            }, r -> "score " + r.summary().score() + ", " + r.findings().size() + " constat(s)");
            for (ReportExporter exporter : exporters) {
                Path target = repository.artifactsDir(job.id()).resolve(exporter.artifact().fileName());
                steps.optional(STEP_EXPORT_PREFIX + exporter.artifact().name().toLowerCase(Locale.ROOT), () -> {
                    exporter.export(report, target);
                    return target;
                }, f -> f.getFileName().toString(), null);
            }
            return report;
        } finally {
            if (!settings.keepWorkspace()) {
                deleteQuietly(workspace);
            }
        }
    }

    private void prepare(FetchedSource source, ScanResult scan, StepRecorder steps) {
        for (SourcePreparer preparer : preparers) {
            String step = STEP_PREPARE_PREFIX + preparer.name();
            if (!DISPOSABLE_SOURCE_KIND.equals(source.kind())) {
                steps.skipped(step, "dossier local non modifié");
                continue;
            }
            List<String> notes = steps.optional(step, () -> preparer.prepare(source.root(), scan),
                    n -> n.size() + " action(s)", List.of());
            steps.warn(notes);
        }
    }

    private SbomResult generateSbom(AnalysisRequest request, FetchedSource source, ScanResult scan, Path rawDir,
                                    StepRecorder steps) {
        Set<Language> languages = EnumSet.noneOf(Language.class);
        scan.languages().stream().filter(l -> !NON_SBOM_LANGUAGES.contains(l)).forEach(languages::add);
        if (!request.runCdxgen()) {
            steps.skipped(STEP_SBOM, "désactivé dans la demande");
            return SbomResult.empty();
        }
        if (languages.isEmpty()) {
            steps.skipped(STEP_SBOM, "aucun langage supporté détecté");
            return SbomResult.empty();
        }
        SbomResult sbom = steps.optional(STEP_SBOM,
                () -> sbomGenerator.generate(source.root(), languages, rawDir,
                        settings.cdxgenTimeout(request.cdxgenTimeoutSeconds())),
                r -> r.boms().size() + " BOM, " + r.reachablesSlices().size() + " slice(s) de flux",
                SbomResult.empty());
        steps.warn(sbom.warnings());
        return sbom;
    }

    private List<Library> collectLibraries(AnalysisRequest request, SbomResult sbom, StepRecorder steps) {
        if (sbom.boms().isEmpty()) {
            steps.skipped(STEP_LIBRARIES, "pas de SBOM");
            steps.skipped(STEP_VULNERABILITIES, "pas de SBOM");
            return List.of();
        }
        List<Library> libraries = steps.optional(STEP_LIBRARIES, () -> libraryReader.read(sbom),
                l -> l.size() + " dépendance(s)", List.of());
        if (!request.scanVulnerabilities() || libraries.isEmpty()) {
            steps.skipped(STEP_VULNERABILITIES, request.scanVulnerabilities() ? "aucune dépendance" : "désactivé");
            return libraries;
        }
        Map<String, List<Vulnerability>> found = steps.optional(STEP_VULNERABILITIES,
                () -> vulnerabilityScanner.scan(libraries),
                m -> m.values().stream().mapToInt(List::size).sum() + " vulnérabilité(s)", Map.of());
        return libraries.stream()
                .map(l -> l.withVulnerabilities(found.getOrDefault(l.purl(), List.of())))
                .toList();
    }

    private Map<String, String> toolVersions() {
        Map<String, String> versions = new LinkedHashMap<>();
        versions.put("chiffrium", settings.toolVersion());
        versions.put("cdxgen", sbomGenerator.version());
        return versions;
    }

    private static void createDirectories(Path dir) {
        try {
            Files.createDirectories(dir);
        } catch (IOException e) {
            throw new UncheckedIOException("Impossible de créer " + dir, e);
        }
    }

    static void deleteQuietly(Path dir) {
        if (!Files.exists(dir)) {
            return;
        }
        try {
            Files.walkFileTree(dir, new SimpleFileVisitor<>() {
                @Override
                public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) throws IOException {
                    file.toFile().setWritable(true);
                    Files.deleteIfExists(file);
                    return FileVisitResult.CONTINUE;
                }

                @Override
                public FileVisitResult postVisitDirectory(Path d, IOException exc) throws IOException {
                    Files.deleteIfExists(d);
                    return FileVisitResult.CONTINUE;
                }
            });
        } catch (IOException e) {
            LOG.warn("Suppression incomplète de l'espace de travail {}", dir, e);
        }
    }
}
