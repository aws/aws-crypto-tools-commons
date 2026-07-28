package aws.cryptography.esdk.testserver.tests;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Unit tests for {@link FeatureDeclarations} parsing, lookup, and the
 * configuration-error paths of Requirement 9.3: an absent registry, absent
 * language, or absent (language, Feature) pair is a configuration error when
 * queried — Feature support is never assumed.
 *
 * <p>These tests exercise the package-private {@code parse} factory directly so
 * they never touch the JVM-wide singleton, system properties, or any
 * Language_Server. (The jqwik property tests over the FeatureGate and property
 * plumbing are separate tasks.)
 */
class FeatureDeclarationsTest {

    private static final String FEATURES =
        "java:streaming=true;MPL=true,python:streaming=true;MPL=false";
    private static final String CATALOG = "streaming,MPL";

    // ------------------------------------------------------------------ parsing

    @Test
    @DisplayName("parses the design's example formats and looks up support per (language, Feature)")
    void parsesDeclarationsAndCatalog() {
        FeatureDeclarations declarations = FeatureDeclarations.parse(FEATURES, CATALOG);

        assertTrue(declarations.isSupported("java", "streaming"));
        assertTrue(declarations.isSupported("java", "MPL"));
        assertTrue(declarations.isSupported("python", "streaming"));
        assertFalse(declarations.isSupported("python", "MPL"));
        assertEquals(List.of("streaming", "MPL"), declarations.catalog());
        assertEquals(Set.of("java", "python"), declarations.languages());
    }

    @Test
    @DisplayName("tolerates surrounding whitespace and empty CSV tokens")
    void toleratesWhitespace() {
        FeatureDeclarations declarations = FeatureDeclarations.parse(
            "  java : streaming = true ; MPL = false , ", " streaming ,, MPL , ");

        assertTrue(declarations.isSupported("java", "streaming"));
        assertFalse(declarations.isSupported("java", "MPL"));
        assertEquals(List.of("streaming", "MPL"), declarations.catalog());
    }

    // ---------------------------------------------- absent configuration errors

    @Test
    @DisplayName("absent features property is a configuration error when queried, not an assumption")
    void absentDeclarationsFailOnQuery() {
        FeatureDeclarations declarations = FeatureDeclarations.parse(null, CATALOG);

        IllegalStateException e = assertThrows(IllegalStateException.class,
            () -> declarations.isSupported("java", "streaming"));
        assertTrue(e.getMessage().contains(FeatureDeclarations.FEATURES_PROPERTY));
        // The catalog side is independently configured and still readable.
        assertEquals(List.of("streaming", "MPL"), declarations.catalog());
    }

    @Test
    @DisplayName("absent featureCatalog property is a configuration error when queried")
    void absentCatalogFailsOnQuery() {
        FeatureDeclarations declarations = FeatureDeclarations.parse(FEATURES, "  ");

        IllegalStateException e = assertThrows(IllegalStateException.class, declarations::catalog);
        assertTrue(e.getMessage().contains(FeatureDeclarations.CATALOG_PROPERTY));
    }

    @Test
    @DisplayName("a language absent from the registry is a configuration error naming the language")
    void absentLanguageFails() {
        FeatureDeclarations declarations = FeatureDeclarations.parse(FEATURES, CATALOG);

        IllegalStateException e = assertThrows(IllegalStateException.class,
            () -> declarations.isSupported("rust", "streaming"));
        assertTrue(e.getMessage().contains("rust"));
    }

    @Test
    @DisplayName("a (language, Feature) pair absent from the registry is a configuration error naming both")
    void absentFeatureForLanguageFails() {
        FeatureDeclarations declarations = FeatureDeclarations.parse(FEATURES, CATALOG);

        IllegalStateException e = assertThrows(IllegalStateException.class,
            () -> declarations.isSupported("java", "quantum"));
        assertTrue(e.getMessage().contains("java"));
        assertTrue(e.getMessage().contains("quantum"));
    }

    // --------------------------------------------------------- malformed input

    @Test
    @DisplayName("rejects malformed declaration entries")
    void rejectsMalformedEntries() {
        // Missing ':' separating language from declarations.
        assertThrows(IllegalArgumentException.class,
            () -> FeatureDeclarations.parse("java streaming=true", CATALOG));
        // Missing '=' inside a declaration.
        assertThrows(IllegalArgumentException.class,
            () -> FeatureDeclarations.parse("java:streaming", CATALOG));
        // Support value must be exactly 'true' or 'false' — never coerced.
        assertThrows(IllegalArgumentException.class,
            () -> FeatureDeclarations.parse("java:streaming=yes", CATALOG));
        // A language entry with zero declarations.
        assertThrows(IllegalArgumentException.class,
            () -> FeatureDeclarations.parse("java:", CATALOG));
    }

    @Test
    @DisplayName("rejects duplicate languages and duplicate Features within a language")
    void rejectsDuplicates() {
        assertThrows(IllegalArgumentException.class,
            () -> FeatureDeclarations.parse("java:streaming=true,java:MPL=true", CATALOG));
        assertThrows(IllegalArgumentException.class,
            () -> FeatureDeclarations.parse("java:streaming=true;streaming=false", CATALOG));
    }

    @Test
    @DisplayName("rejects a duplicate Feature name in the catalog")
    void rejectsDuplicateCatalogName() {
        assertThrows(IllegalArgumentException.class,
            () -> FeatureDeclarations.parse(FEATURES, "streaming,streaming"));
    }
}
