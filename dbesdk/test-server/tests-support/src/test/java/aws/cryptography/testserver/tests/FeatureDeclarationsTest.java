package aws.cryptography.testserver.tests;

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
 * source, or absent (source, Feature) pair is a configuration error when
 * queried — Feature support is never assumed. Support is keyed by the full
 * {@code (language, majorVersion, repo)} source identity.
 *
 * <p>These tests exercise the package-private {@code parse} factory directly so
 * they never touch the JVM-wide singleton, system properties, or any
 * Language_Server. (The jqwik property tests over the FeatureGate and property
 * plumbing are separate tasks.)
 */
class FeatureDeclarationsTest {

    private static final String REPO = "dbe";
    private static final String FEATURES =
        "java:3:dbe:streaming=true;MPL=true,python:3:dbe:streaming=true;MPL=false";
    private static final String CATALOG = "streaming,MPL";

    // ------------------------------------------------------------------ parsing

    @Test
    @DisplayName("parses the design's example formats and looks up support per (language, major, repo, Feature)")
    void parsesDeclarationsAndCatalog() {
        FeatureDeclarations declarations = FeatureDeclarations.parse(FEATURES, CATALOG);

        assertTrue(declarations.isSupported("java", 3, REPO, "streaming"));
        assertTrue(declarations.isSupported("java", 3, REPO, "MPL"));
        assertTrue(declarations.isSupported("python", 3, REPO, "streaming"));
        assertFalse(declarations.isSupported("python", 3, REPO, "MPL"));
        assertEquals(List.of("streaming", "MPL"), declarations.catalog());
        assertEquals(Set.of("java:3:dbe", "python:3:dbe"), declarations.sources());
    }

    @Test
    @DisplayName("distinguishes sources that share a language by major version and repo")
    void distinguishesByMajorVersionAndRepo() {
        FeatureDeclarations declarations =
            FeatureDeclarations.parse("java:3:dbe:streaming=true", "streaming");

        assertTrue(declarations.isSupported("java", 3, REPO, "streaming"));
        // A different major version or repo is a different source, absent from
        // the registry — a configuration error, never assumed support.
        assertThrows(IllegalStateException.class,
            () -> declarations.isSupported("java", 2, REPO, "streaming"));
        assertThrows(IllegalStateException.class,
            () -> declarations.isSupported("java", 3, "other-repo", "streaming"));
    }

    @Test
    @DisplayName("tolerates surrounding whitespace and empty CSV tokens")
    void toleratesWhitespace() {
        FeatureDeclarations declarations = FeatureDeclarations.parse(
            "  java : 3 : dbe : streaming = true ; MPL = false , ", " streaming ,, MPL , ");

        assertTrue(declarations.isSupported("java", 3, REPO, "streaming"));
        assertFalse(declarations.isSupported("java", 3, REPO, "MPL"));
        assertEquals(List.of("streaming", "MPL"), declarations.catalog());
    }

    // ---------------------------------------------- absent configuration errors

    @Test
    @DisplayName("absent features property is a configuration error when queried, not an assumption")
    void absentDeclarationsFailOnQuery() {
        FeatureDeclarations declarations = FeatureDeclarations.parse(null, CATALOG);

        IllegalStateException e = assertThrows(IllegalStateException.class,
            () -> declarations.isSupported("java", 3, REPO, "streaming"));
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
    @DisplayName("a source absent from the registry is a configuration error naming the source")
    void absentSourceFails() {
        FeatureDeclarations declarations = FeatureDeclarations.parse(FEATURES, CATALOG);

        IllegalStateException e = assertThrows(IllegalStateException.class,
            () -> declarations.isSupported("rust", 3, REPO, "streaming"));
        assertTrue(e.getMessage().contains("rust"));
    }

    @Test
    @DisplayName("a (source, Feature) pair absent from the registry is a configuration error naming both")
    void absentFeatureForSourceFails() {
        FeatureDeclarations declarations = FeatureDeclarations.parse(FEATURES, CATALOG);

        IllegalStateException e = assertThrows(IllegalStateException.class,
            () -> declarations.isSupported("java", 3, REPO, "quantum"));
        assertTrue(e.getMessage().contains("java"));
        assertTrue(e.getMessage().contains("quantum"));
    }

    // --------------------------------------------------------- malformed input

    @Test
    @DisplayName("rejects malformed declaration entries")
    void rejectsMalformedEntries() {
        // Fewer than the four language:major:repo:decls segments.
        assertThrows(IllegalArgumentException.class,
            () -> FeatureDeclarations.parse("java:streaming=true", CATALOG));
        // Non-integer major version.
        assertThrows(IllegalArgumentException.class,
            () -> FeatureDeclarations.parse("java:x:dbe:streaming=true", CATALOG));
        // Missing '=' inside a declaration.
        assertThrows(IllegalArgumentException.class,
            () -> FeatureDeclarations.parse("java:3:dbe:streaming", CATALOG));
        // Support value must be exactly 'true' or 'false' — never coerced.
        assertThrows(IllegalArgumentException.class,
            () -> FeatureDeclarations.parse("java:3:dbe:streaming=yes", CATALOG));
        // A source entry with zero declarations.
        assertThrows(IllegalArgumentException.class,
            () -> FeatureDeclarations.parse("java:3:dbe:", CATALOG));
    }

    @Test
    @DisplayName("rejects duplicate sources and duplicate Features within a source")
    void rejectsDuplicates() {
        assertThrows(IllegalArgumentException.class,
            () -> FeatureDeclarations.parse("java:3:dbe:streaming=true,java:3:dbe:MPL=true", CATALOG));
        assertThrows(IllegalArgumentException.class,
            () -> FeatureDeclarations.parse("java:3:dbe:streaming=true;streaming=false", CATALOG));
    }

    @Test
    @DisplayName("rejects a duplicate Feature name in the catalog")
    void rejectsDuplicateCatalogName() {
        assertThrows(IllegalArgumentException.class,
            () -> FeatureDeclarations.parse(FEATURES, "streaming,streaming"));
    }

    // ------------------------------------------- raw-RSA padding capability

    @Test
    @DisplayName("a declared padding subset is supported exactly; other sources support every scheme")
    void paddingSubsetIsExact() {
        FeatureDeclarations declarations = FeatureDeclarations.parse(
            FEATURES, CATALOG, "c:3:dbe:PKCS1;OAEP_SHA1_MGF1;OAEP_SHA256_MGF1");

        assertTrue(declarations.supportsRawRsaPadding("c", 3, REPO, "PKCS1"));
        assertTrue(declarations.supportsRawRsaPadding("c", 3, REPO, "OAEP_SHA256_MGF1"));
        assertFalse(declarations.supportsRawRsaPadding("c", 3, REPO, "OAEP_SHA384_MGF1"));
        assertFalse(declarations.supportsRawRsaPadding("c", 3, REPO, "OAEP_SHA512_MGF1"));
        // java declared no restriction: every scheme is supported.
        assertTrue(declarations.supportsRawRsaPadding("java", 3, REPO, "OAEP_SHA512_MGF1"));
    }

    @Test
    @DisplayName("an absent padding property means every source supports every scheme")
    void absentPaddingPropertyMeansAllSupported() {
        FeatureDeclarations declarations = FeatureDeclarations.parse(FEATURES, CATALOG, null);

        assertTrue(declarations.supportsRawRsaPadding("java", 3, REPO, "OAEP_SHA384_MGF1"));
        assertTrue(declarations.supportsRawRsaPadding("python", 3, REPO, "PKCS1"));
    }

    @Test
    @DisplayName("rejects malformed padding entries: duplicates, empty lists")
    void rejectsMalformedPaddingEntries() {
        // Duplicate scheme within a source.
        assertThrows(IllegalArgumentException.class,
            () -> FeatureDeclarations.parse(FEATURES, CATALOG, "c:3:dbe:PKCS1;PKCS1"));
        // Duplicate source.
        assertThrows(IllegalArgumentException.class,
            () -> FeatureDeclarations.parse(FEATURES, CATALOG, "c:3:dbe:PKCS1,c:3:dbe:PKCS1"));
        // A source with zero schemes.
        assertThrows(IllegalArgumentException.class,
            () -> FeatureDeclarations.parse(FEATURES, CATALOG, "c:3:dbe:"));
        // Fewer than the four language:major:repo:schemes segments.
        assertThrows(IllegalArgumentException.class,
            () -> FeatureDeclarations.parse(FEATURES, CATALOG, "PKCS1"));
    }
}
