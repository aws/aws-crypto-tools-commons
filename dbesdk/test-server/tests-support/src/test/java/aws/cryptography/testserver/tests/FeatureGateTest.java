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
 * Unit tests for the {@link FeatureGate} decision logic, exercising the
 * package-private injected-registry
 * variant so no system properties, singleton state, or Language_Server are
 * involved. (The jqwik property test over the gate is a separate task.)
 *
 * <p>The registry is keyed by the full {@code (language, majorVersion, repo)}
 * source identity, so every target here is major {@code 3} of repo {@code dbe}
 * and each declaration string is keyed to match; the visible skip message names
 * the target {@code label()} ({@code <language>-v<major>}).
 */
class FeatureGateTest {

    private static final String CATALOG = "streaming,MPL";
    private static final String REPO = "dbe";

    private static FeatureDeclarations registry(String features) {
        return FeatureDeclarations.parse(features, CATALOG);
    }

    private static LanguageServerTarget target(String language) {
        return new LanguageServerTarget(
            language, 3, REPO, URI.create("http://127.0.0.1:0/" + language));
    }

    private static TargetPair pair(String encryptLanguage, String decryptLanguage) {
        return new TargetPair(target(encryptLanguage), target(decryptLanguage));
    }

    // ------------------------------------------------------------ pass-through

    @Test
    @DisplayName("permits execution when every combination target declares every required Feature supported")
    void permitsWhenAllSupported() {
        FeatureDeclarations declarations =
            registry("java:3:dbe:streaming=true;MPL=true,python:3:dbe:streaming=true;MPL=true");

        assertDoesNotThrow(() ->
            FeatureGate.require(Set.of("streaming", "MPL"), pair("java", "python"), declarations));
        // Same-target pairs gate on the one source's declaration only.
        assertDoesNotThrow(() ->
            FeatureGate.require(Set.of("streaming"), pair("java", "java"), declarations));
    }

    // ------------------------------------------------------- feature-gated skip

    @Test
    @DisplayName("skips via TestAbortedException with the exact gating message when one target declares a Feature unsupported")
    void skipsWithExactMessage() {
        FeatureDeclarations declarations =
            registry("java:3:dbe:streaming=true;MPL=true,python:3:dbe:streaming=true;MPL=false");

        TestAbortedException skip = assertThrows(TestAbortedException.class, () ->
            FeatureGate.require(Set.of("MPL"), pair("java", "python"), declarations));

        assertEquals("feature-gated skip: feature=MPL unsupported by [python-v3]", skip.getMessage());
    }

    @Test
    @DisplayName("the skip message names exactly the unsupporting targets")
    void skipNamesExactlyTheUnsupportingTargets() {
        FeatureDeclarations declarations =
            registry("java:3:dbe:streaming=false;MPL=true,python:3:dbe:streaming=false;MPL=true");

        TestAbortedException skip = assertThrows(TestAbortedException.class, () ->
            FeatureGate.require(Set.of("streaming"), pair("java", "python"), declarations));

        assertEquals("feature-gated skip: feature=streaming unsupported by [java-v3, python-v3]",
            skip.getMessage());
    }

    @Test
    @DisplayName("the skip message names each gating Feature when several gate the combination")
    void skipNamesEachGatingFeature() {
        FeatureDeclarations declarations =
            registry("java:3:dbe:streaming=true;MPL=true,python:3:dbe:streaming=false;MPL=false");

        TestAbortedException skip = assertThrows(TestAbortedException.class, () ->
            FeatureGate.require(Set.of("streaming", "MPL"), pair("java", "python"), declarations));

        assertTrue(skip.getMessage().startsWith("feature-gated skip: "), skip.getMessage());
        assertTrue(skip.getMessage().contains("feature=streaming unsupported by [python-v3]"),
            skip.getMessage());
        assertTrue(skip.getMessage().contains("feature=MPL unsupported by [python-v3]"),
            skip.getMessage());
    }

    // ------------------------------------------------------ unknown Feature (9.11)

    @Test
    @DisplayName("an unknown Feature is a test failure naming the Test and the Feature, never a skip")
    void unknownFeatureIsATestFailure() {
        FeatureDeclarations declarations =
            registry("java:3:dbe:streaming=true;MPL=true,python:3:dbe:streaming=true;MPL=true");

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
            "java:3:dbe:streaming=true;extra=true,python:3:dbe:streaming=true;extra=false", CATALOG);

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
    @DisplayName("a combination target without a declaration is a configuration failure")
    void missingSourceDeclarationIsAConfigurationFailure() {
        FeatureDeclarations declarations = registry("java:3:dbe:streaming=true;MPL=true");

        IllegalStateException failure = assertThrows(IllegalStateException.class, () ->
            FeatureGate.require(Set.of("streaming"), pair("java", "python"), declarations));
        assertTrue(failure.getMessage().contains("python"), failure.getMessage());
    }

    @Test
    @DisplayName("an unconfigured Feature_Catalog is a configuration failure")
    void unconfiguredCatalogIsAConfigurationFailure() {
        FeatureDeclarations declarations = FeatureDeclarations.parse(
            "java:3:dbe:streaming=true;MPL=true,python:3:dbe:streaming=true;MPL=true", null);

        assertThrows(IllegalStateException.class, () ->
            FeatureGate.require(Set.of("streaming"), pair("java", "python"), declarations));
    }

    // ------------------------------------------------------ padding-gated skip

    @Test
    @DisplayName("skips with the exact padding-gated message when either combination target excludes a scheme")
    void skipsWhenEitherTargetExcludesTheScheme() {
        FeatureDeclarations declarations = FeatureDeclarations.parse(
            "java:3:dbe:streaming=true;MPL=true,c:3:dbe:streaming=true;MPL=true",
            CATALOG, "c:3:dbe:PKCS1;OAEP_SHA1_MGF1;OAEP_SHA256_MGF1");

        TestAbortedException encryptSide = assertThrows(TestAbortedException.class, () ->
            FeatureGate.requireRawRsaPaddings(
                Set.of("OAEP_SHA384_MGF1"), pair("c", "java"), declarations));
        assertEquals("padding-gated skip: rawRsaPadding=OAEP_SHA384_MGF1 unsupported by [c-v3]",
            encryptSide.getMessage());

        TestAbortedException decryptSide = assertThrows(TestAbortedException.class, () ->
            FeatureGate.requireRawRsaPaddings(
                Set.of("OAEP_SHA512_MGF1"), pair("java", "c"), declarations));
        assertEquals("padding-gated skip: rawRsaPadding=OAEP_SHA512_MGF1 unsupported by [c-v3]",
            decryptSide.getMessage());
    }

    @Test
    @DisplayName("permits execution when both combination targets support every required scheme")
    void permitsWhenBothTargetsSupportTheSchemes() {
        FeatureDeclarations declarations = FeatureDeclarations.parse(
            "java:3:dbe:streaming=true;MPL=true,c:3:dbe:streaming=true;MPL=true",
            CATALOG, "c:3:dbe:PKCS1;OAEP_SHA1_MGF1;OAEP_SHA256_MGF1");

        assertDoesNotThrow(() -> FeatureGate.requireRawRsaPaddings(
            Set.of("PKCS1", "OAEP_SHA256_MGF1"),
            pair("java", "c"), declarations));
        // Sources that declared no restriction support every scheme.
        assertDoesNotThrow(() -> FeatureGate.requireRawRsaPaddings(
            Set.of("OAEP_SHA512_MGF1"), pair("java", "java"), declarations));
        // No required schemes (a non-raw-RSA vector): never gates.
        assertDoesNotThrow(() -> FeatureGate.requireRawRsaPaddings(
            Set.of(), pair("c", "c"), declarations));
    }
}
