package aws.cryptography.testserver.orchestrator.run;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.URI;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Unit tests for {@link TestRunInput}'s property-formatting helpers and the
 * Feature_Declaration flattening. The formats are normative — the Tests-module
 * parsers ({@code LanguageServerRegistry}, {@code FeatureDeclarations}) consume
 * these exact shapes.
 */
class TestRunInputTest {

    @Test
    @DisplayName("targets format is the normative lang:major=url CSV (Req 2.2)")
    void formatsTargets() {
        List<TestTarget> targets = List.of(
            new TestTarget("java", 3, "dbe", URI.create("http://127.0.0.1:8091")),
            new TestTarget("python", 4, "dbe", URI.create("http://127.0.0.1:8092")));

        assertEquals("java:3:dbe=http://127.0.0.1:8091,python:4:dbe=http://127.0.0.1:8092",
            TestRunInput.formatTargets(targets));
    }

    @Test
    @DisplayName("features format is the normative lang:major:repo:feat=bool[;feat=bool] CSV (Req 9.3)")
    void formatsFeatures() {
        Map<String, Map<String, Boolean>> features = new LinkedHashMap<>();
        features.put("java:3:dbe", declaration("streaming", true, "MPL", true));
        features.put("python:3:dbe", declaration("streaming", true, "MPL", true));

        assertEquals("java:3:dbe:streaming=true;MPL=true,python:3:dbe:streaming=true;MPL=true",
            TestRunInput.formatFeatures(features));
    }

    @Test
    @DisplayName("an unsupported Feature is formatted as false")
    void formatsUnsupportedFeatureAsFalse() {
        Map<String, Map<String, Boolean>> features = new LinkedHashMap<>();
        features.put("rust:1:dbe", declaration("streaming", false, "MPL", true));

        assertEquals("rust:1:dbe:streaming=false;MPL=true", TestRunInput.formatFeatures(features));
    }

    @Test
    @DisplayName("featureCatalog format is the Feature-name CSV, catalog verbatim")
    void formatsFeatureCatalog() {
        assertEquals("streaming,MPL",
            TestRunInput.formatFeatureCatalog(List.of("streaming", "MPL")));
    }

    @Test
    @DisplayName("flattening maps supportedFeatures to true and unsupportedFeatures to false, in catalog order")
    void flattensDeclaration() {
        Map<String, Boolean> flattened = TestRunInput.flattenDeclaration(
            List.of("streaming", "MPL"),
            List.of("MPL"),
            List.of("streaming"));

        assertEquals(List.of("streaming", "MPL"), List.copyOf(flattened.keySet()),
            "flattened Features must follow catalog order");
        assertEquals(Boolean.FALSE, flattened.get("streaming"));
        assertEquals(Boolean.TRUE, flattened.get("MPL"));
    }

    @Test
    @DisplayName("flattening treats null declaration arrays as absent")
    void flattensNullArrays() {
        Map<String, Boolean> flattened = TestRunInput.flattenDeclaration(
            List.of("streaming", "MPL"), List.of("streaming", "MPL"), null);

        assertEquals(Map.of("streaming", true, "MPL", true), flattened);
        assertTrue(TestRunInput.flattenDeclaration(List.of("streaming"), null, null).isEmpty(),
            "no declared Features flatten to an empty map");
    }

    @Test
    @DisplayName("formats declared raw-RSA padding capabilities as lang:major:repo:SCHEME[;SCHEME…] CSV")
    void formatsRawRsaPaddingSchemes() {
        Map<String, List<String>> schemes = new LinkedHashMap<>();
        schemes.put("c:1:dbe", List.of("PKCS1", "OAEP_SHA1_MGF1", "OAEP_SHA256_MGF1"));
        schemes.put("python:1:dbe", List.of("OAEP_SHA512_MGF1"));

        assertEquals("c:1:dbe:PKCS1;OAEP_SHA1_MGF1;OAEP_SHA256_MGF1,python:1:dbe:OAEP_SHA512_MGF1",
            TestRunInput.formatRawRsaPaddingSchemes(schemes));
        assertEquals("", TestRunInput.formatRawRsaPaddingSchemes(Map.of()));
    }

    @Test
    @DisplayName("the record preserves target, language, and Feature ordering")
    void preservesOrdering() {
        Map<String, Map<String, Boolean>> features = new LinkedHashMap<>();
        features.put("python:4:dbe", declaration("streaming", true, "MPL", true));
        features.put("java:3:dbe", declaration("MPL", true, "streaming", true));

        TestRunInput input = new TestRunInput(
            List.of(new TestTarget("python", 4, "dbe", URI.create("http://127.0.0.1:8092")),
                new TestTarget("java", 3, "dbe", URI.create("http://127.0.0.1:8091"))),
            features,
            List.of("streaming", "MPL"),
            Map.of(),
            "java");

        assertEquals("python:4:dbe=http://127.0.0.1:8092,java:3:dbe=http://127.0.0.1:8091",
            TestRunInput.formatTargets(input.targets()));
        assertEquals("python:4:dbe:streaming=true;MPL=true,java:3:dbe:MPL=true;streaming=true",
            TestRunInput.formatFeatures(input.features()));
        assertFalse(input.featureCatalog().isEmpty());
    }

    @Test
    @DisplayName("the reference implementation is carried verbatim and must be non-blank")
    void carriesReferenceImplementation() {
        List<TestTarget> targets =
            List.of(new TestTarget("java", 3, "dbe", URI.create("http://127.0.0.1:8091")));

        assertEquals("python",
            new TestRunInput(targets, Map.of(), List.of(), Map.of(), "python")
                .referenceImplementation());
        org.junit.jupiter.api.Assertions.assertThrows(IllegalArgumentException.class,
            () -> new TestRunInput(targets, Map.of(), List.of(), Map.of(), " "),
            "a blank reference implementation must be rejected");
    }

    private static Map<String, Boolean> declaration(
            String f1, boolean v1, String f2, boolean v2) {
        Map<String, Boolean> declaration = new LinkedHashMap<>();
        declaration.put(f1, v1);
        declaration.put(f2, v2);
        return declaration;
    }
}
