package com.chiffrium.application.graph;

import com.chiffrium.TestSupport;
import com.chiffrium.application.port.CallEdgeExtractor.CallEdge;
import com.chiffrium.application.port.CryptoDetector.FileFlow;
import com.chiffrium.domain.model.CallGraph;
import com.chiffrium.domain.model.CryptoAsset;
import com.chiffrium.domain.model.DetectionSource;
import com.chiffrium.domain.model.Language;
import com.chiffrium.domain.model.Occurrence;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

class CallGraphBuilderTest {

    @Test
    void reducesQualifiedNamesToContainerAndFunction() {
        assertThat(CallGraphBuilder.functionKey("com.acme.Crypto.decrypt:byte[](byte[])")).isEqualTo("Crypto.decrypt");
        assertThat(CallGraphBuilder.functionKey("Crypto.decrypt")).isEqualTo("Crypto.decrypt");
        assertThat(CallGraphBuilder.functionKey("javax.crypto.Cipher.init(int)")).isEqualTo("Cipher.init");
    }

    @Test
    void linksAssetsFunctionsCallersFilesAndCryptoApis() {
        Occurrence occurrence = new Occurrence("Crypto.java", 10, 1, "Crypto.encrypt", null, Language.JAVA,
                DetectionSource.RULES, "r", Set.of());
        CryptoAsset aes = TestSupport.ASSETS.fromAlgorithmName("AES/GCM/NoPadding", occurrence, Set.of(),
                DetectionSource.RULES, null);
        List<FileFlow> flows = List.of(new FileFlow("private.pem", "Crypto.java", 30, "Crypto.save", true),
                new FileFlow("private.pem", "Loader.java", 5, "Loader.load", false));
        List<CallEdge> calls = List.of(
                new CallEdge("com.acme.Service.handle:void()", "com.acme.Crypto.encrypt:byte[](byte[])", "Service.java", 3, false),
                new CallEdge("com.acme.Api.post:void()", "com.acme.Service.handle:void()", "Api.java", 8, false),
                new CallEdge("com.acme.Crypto.encrypt:byte[](byte[])", "javax.crypto.Cipher.doFinal:byte[](byte[])",
                        "Crypto.java", 12, true),
                new CallEdge("com.acme.Other.log:void()", "java.util.Logger.info", "Other.java", 1, true));

        CallGraph graph = new CallGraphBuilder().build(List.of(aes), flows, calls).graph();

        assertThat(graph.nodes()).extracting(CallGraph.Node::id)
                .contains("asset:" + aes.bomRef(), "fn:Crypto.encrypt", "fn:Service.handle", "fn:Api.post",
                        "file:private.pem", "fn:Crypto.save", "fn:Loader.load", "api:Cipher.doFinal")
                .doesNotContain("fn:Other.log", "api:Logger.info");
        assertThat(graph.edges()).contains(
                new CallGraph.Edge("fn:Crypto.encrypt", "asset:" + aes.bomRef(), CallGraph.EdgeKind.USES),
                new CallGraph.Edge("fn:Service.handle", "fn:Crypto.encrypt", CallGraph.EdgeKind.CALLS),
                new CallGraph.Edge("fn:Crypto.save", "file:private.pem", CallGraph.EdgeKind.PRODUCES),
                new CallGraph.Edge("file:private.pem", "fn:Loader.load", CallGraph.EdgeKind.CONSUMES),
                new CallGraph.Edge("fn:Crypto.encrypt", "api:Cipher.doFinal", CallGraph.EdgeKind.CALLS));
    }
}
