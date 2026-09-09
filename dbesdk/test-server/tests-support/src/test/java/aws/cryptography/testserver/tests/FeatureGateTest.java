package aws.cryptography.testserver.tests;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.URI;
import java.util.Set;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.opentest4j.TestAbortedException;

/**
 * Unit tests for the {@link FeatureGate} decision logic (Requirements 9.3,
 * 9.4, 9.5, 9.6, 9.11), exercising the package-private injected-registry
 * variant so no system properties, singleton state, or Language_Server are
 * involved. (The jqwik property test over the gate is a separate task.)
 */
class FeatureGateTest {

    private static final String CATALOG = "streaming,MPL";

    private static FeatureDeclarations registry(String features) {
        return FeatureDeclarations.parse(features, CATALOG);
    }

    private static LanguageServerTarget target(String language, int majorVersion) {
        return new LanguageServerTarget(
            language, majorVersion, URI.create("http://127.0.0.1:0/" + language));
    }

    private static TargetPair pair(String encryptLanguage, String decryptLanguage) {
        return new TargetPair(target(encryptLanguage, 3), target(decryptLanguage, 4));
    }

    // ------------------------------------------------------------ pass-through

    @Test
    @DisplayName("permits execution when every combination language declares every required Feature supported")
    void permitsWhenAllSupported() {
        FeatureDeclarations declarations =
            registry("java:streaming=true;MPL=true,python:streaming=true;MPL=true");

        assertDoesNotThrow(() ->
            FeatureGate.require(Set.of("streaming", "MPL"), pair("java", "python"), declarations));
        // Same-target pairs gate on the one language's declaration only.
        assertDoesNotThrow(() ->
            FeatureGate.require(Set.of("streaming"), pair("java", "java"), declarations));
    }

    // ------------------------------------------------------- feature-gated skip

    @Test
    @DisplayName("skips via TestAbortedException with the exact gating message when one language declares a Feature unsupported")
    void skipsWithExactMessage() {
        FeatureDeclarations declarations =
            registry("java:streaming=true;MPL=true,python:streaming=true;MPL=false");

        TestAbortedException skip = assertThrows(TestAbortedException.class, () ->
            FeatureGate.require(Set.of("MPL"), pair("java", "python"), declarations));

        assertEquals("feature-gated skip: feature=MPL unsupported by [python]", skip.getMessage());
    }

    @Test
    @DisplayName("the skip message names exactly the unsupporting languages")
    void skipNamesExactlyTheUnsupportingLanguages() {
        FeatureDeclarations declarations =
            registry("java:streaming=false;MPL=true,python:streaming=false;MPL=true");

        TestAbortedException skip = assertThrows(TestAbortedException.class, () ->
            FeatureGate.require(Set.of("streaming"), pair("java", "python"), declarations));

        assertEquals("feature-gated skip: feature=streaming unsupported by [java, python]",
            skip.getMessage());
    }

    @Test
    @DisplayName("the skip message names each gating Feature when several gate the combination")
    void skipNamesEachGatingFeature() {
        FeatureDeclarations declarations =
            registry("java:streaming=true;MPL=true,python:streaming=false;MPL=false");

        TestAbortedException skip = assertThrows(TestAbortedException.class, () ->
            FeatureGate.require(Set.of("streaming", "MPL"), pair("java", "python"), declarations));

        assertTrue(skip.getMessage().startsWith("feature-gated skip: "), skip.getMessage());
        assertTrue(skip.getMessage().contains("feature=streaming unsupported by [python]"),
            skip.getMessage());
        assertTrue(skip.getMessage().contains("feature=MPL unsupported by [python]"),
            skip.getMessage());
    }

    // ------------------------------------------------------ unknown Feature (9.11)

    @Test
    @DisplayName("an unknown Feature is a test failure naming the Test and the Feature, never a skip")
    void unknownFeatureIsATestFailure() {
        FeatureDeclarations declarations =
            registry("java:streaming=true;MPL=true,python:streaming=true;MPL=true");

        AssertionError failure = assertThrows(AssertionError.class, () ->
            FeatureGate.require(Set.of("quantum"), pair("java", "python"), declarations));

        assertTrue(failure.getMessage().contains("quantum"), failure.getMessage());
        // Names the Test (this test method is the gate's caller).
        assertTrue(failure.getMessage().contains("unknownFeatureIsATestFailure"), failure.getMessage());
    }

    @Test
    @DisplayName("the catalog check runs first: an unknown Feature fails even when a declaration would gate it")
    void unknownFeatureCheckedBeforeDeclarations() {
        // 'extra' is declared (unsupported by python) but absent from the
        // catalog — the gate must FAIL, not skip.
        FeatureDeclarations declarations = FeatureDeclarations.parse(
            "java:streaming=true;extra=true,python:streaming=true;extra=false", CATALOG);

        assertThrows(AssertionError.class, () ->
            FeatureGate.require(Set.of("extra"), pair("java", "python"), declarations));
    }

    // ---------------------------------------- missing declarations (9.3)

    @Test
    @DisplayName("an unconfigured declaration registry is a configuration failure, never assumed support")
    void unconfiguredDeclarationsAreAConfigurationFailure() {
        FeatureDeclarations declarations = FeatureDeclarations.parse(null, CATALOG);

        assertThrows(IllegalStateException.class, () ->
            FeatureGate.require(Set.of("streaming"), pair("java", "python"), declarations));
    }

    @Test
    @DisplayName("a combination language without a declaration is a configuration failure")
    void missingLanguageDeclarationIsAConfigurationFailure() {
        FeatureDeclarations declarations = registry("java:streaming=true;MPL=true");

        IllegalStateException failure = assertThrows(IllegalStateException.class, () ->
            FeatureGate.require(Set.of("streaming"), pair("java", "python"), declarations));
        assertTrue(failure.getMessage().contains("python"), failure.getMessage());
    }

    @Test
    @DisplayName("an unconfigured Feature_Catalog is a configuration failure")
    void unconfiguredCatalogIsAConfigurationFailure() {
        FeatureDeclarations declarations = FeatureDeclarations.parse(
            "java:streaming=true;MPL=true,python:streaming=true;MPL=true", null);

        assertThrows(IllegalStateException.class, () ->
            FeatureGate.require(Set.of("streaming"), pair("java", "python"), declarations));
    }

    // ------------------------------------------------------ padding-gated skip

    @Test
    @DisplayName("skips with the exact padding-gated message when either combination language excludes a scheme")
    void skipsWhenEitherLanguageExcludesTheScheme() {
        FeatureDeclarations declarations = FeatureDeclarations.parse(
            "java:streaming=true;MPL=true,c:streaming=true;MPL=true",
            CATALOG, "c:PKCS1;OAEP_SHA1_MGF1;OAEP_SHA256_MGF1");

        TestAbortedException encryptSide = assertThrows(TestAbortedException.class, () ->
            FeatureGate.requireRawRsaPaddings(
                Set.of("OAEP_SHA384_MGF1"), pair("c", "java"), declarations));
        assertEquals("padding-gated skip: rawRsaPadding=OAEP_SHA384_MGF1 unsupported by [c]",
            encryptSide.getMessage());

        TestAbortedException decryptSide = assertThrows(TestAbortedException.class, () ->
            FeatureGate.requireRawRsaPaddings(
                Set.of("OAEP_SHA512_MGF1"), pair("java", "c"), declarations));
        assertEquals("padding-gated skip: rawRsaPadding=OAEP_SHA512_MGF1 unsupported by [c]",
            decryptSide.getMessage());
    }

    @Test
    @DisplayName("permits execution when both combination languages support every required scheme")
    void permitsWhenBothLanguagesSupportTheSchemes() {
        FeatureDeclarations declarations = FeatureDeclarations.parse(
            "java:streaming=true;MPL=true,c:streaming=true;MPL=true",
            CATALOG, "c:PKCS1;OAEP_SHA1_MGF1;OAEP_SHA256_MGF1");

        assertDoesNotThrow(() -> FeatureGate.requireRawRsaPaddings(
            Set.of("PKCS1", "OAEP_SHA256_MGF1"),
            pair("java", "c"), declarations));
        // Languages that declared no restriction support every scheme.
        assertDoesNotThrow(() -> FeatureGate.requireRawRsaPaddings(
            Set.of("OAEP_SHA512_MGF1"), pair("java", "java"), declarations));
        // No required schemes (a non-raw-RSA vector): never gates.
        assertDoesNotThrow(() -> FeatureGate.requireRawRsaPaddings(
            Set.of(), pair("c", "c"), declarations));
    }
}
