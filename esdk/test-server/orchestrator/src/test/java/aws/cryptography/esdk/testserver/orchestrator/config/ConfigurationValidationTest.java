package aws.cryptography.esdk.testserver.orchestrator.config;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Unit tests for {@link ConfigurationValidation} — the structural checks added
 * by the factoring (Requirements 3.2, 3.8, 4.7, 4.11, 7.4, 7.5). All pure: no
 * I/O, nothing cloned. The jqwik coverage lives in
 * {@link ConfigurationSetValidationPropertyTest} (migrated legacy checks) and
 * the task-1.3 Property 1 test.
 */
class ConfigurationValidationTest {

    private static ConfigurationEntry entry(String language, int port) {
        return new ConfigurationEntry(language, 3, port,
            new RepositoryCoordinates("repo-" + language,
                "git@github.com:aws/repo-" + language + ".git", "main", "."),
            new ServerLocation("aws-crypto-tools-commons",
                "git@github.com:aws/aws-crypto-tools-commons.git", "main",
                "esdk/test-server/servers/" + language),
            null, null);
    }

    private static ConfigurationSet set(ConfigurationEntry... entries) {
        return new ConfigurationSet("esdk", List.of("streaming", "MPL"), List.of(entries));
    }

    @Test
    @DisplayName("a complete set with overrides for other configured languages validates")
    void completeSetWithValidOverrideIsAccepted() {
        ConfigurationSetValidation v = ConfigurationValidation.validate(
            set(entry("java", 8091), entry("python", 8092)),
            List.of(entry("python", 8092)),
            "java");
        assertTrue(v.valid(), "expected valid but got: " + v.errors());
    }

    @Test
    @DisplayName("missing serverLocation elements are each named with the language (Req 3.8)")
    void missingServerLocationElementsAreNamed() {
        ConfigurationEntry noLocation = new ConfigurationEntry("java", 3, 8091,
            new RepositoryCoordinates("repo-java", "url", "main", "."),
            new ServerLocation(null, "url", "  ", null),
            null, null);
        ConfigurationSetValidation v = ConfigurationValidation.validate(set(noLocation));
        assertFalse(v.valid());
        assertTrue(v.message().contains("java"), "must name the language: " + v.errors());
        assertTrue(v.message().contains("serverLocation missing repository"), v.message());
        assertTrue(v.message().contains("serverLocation missing ref"), v.message());
        assertTrue(v.message().contains("serverLocation missing path"), v.message());
    }

    @Test
    @DisplayName("an absent serverLocation object is a validation error (Req 3.8)")
    void absentServerLocationIsRejected() {
        ConfigurationEntry noLocation = new ConfigurationEntry("java", 3, 8091,
            new RepositoryCoordinates("repo-java", "url", "main", "."),
            null, null, null);
        ConfigurationSetValidation v = ConfigurationValidation.validate(set(noLocation));
        assertFalse(v.valid());
        assertTrue(v.message().contains("entry java: missing serverLocation"), v.message());
    }

    @Test
    @DisplayName("missing libraryRepository url is named (Req 3.2)")
    void missingLibraryUrlIsNamed() {
        ConfigurationEntry noUrl = new ConfigurationEntry("java", 3, 8091,
            new RepositoryCoordinates("repo-java", null, "main", "."),
            entry("java", 8091).serverLocation(), null, null);
        ConfigurationSetValidation v = ConfigurationValidation.validate(set(noUrl));
        assertFalse(v.valid());
        assertTrue(v.message().contains("entry java: libraryRepository missing url"), v.message());
    }

    @Test
    @DisplayName("missing product and missing Feature_Catalog are rejected (Req 7.4)")
    void missingProductAndCatalogAreRejected() {
        ConfigurationSet bare = new ConfigurationSet(null, null, List.of(entry("java", 8091)));
        ConfigurationSetValidation v = ConfigurationValidation.validate(bare);
        assertFalse(v.valid());
        assertTrue(v.message().contains("missing product"), v.message());
        assertTrue(v.message().contains("missing Feature_Catalog"), v.message());
    }

    @Test
    @DisplayName("duplicate Feature names in the catalog are each named (Req 7.5)")
    void duplicateCatalogFeatureNamesAreNamed() {
        ConfigurationSet dup = new ConfigurationSet("esdk",
            List.of("streaming", "MPL", "streaming", "MPL"),
            List.of(entry("java", 8091)));
        ConfigurationSetValidation v = ConfigurationValidation.validate(dup);
        assertFalse(v.valid());
        assertTrue(v.message().contains("duplicate Feature name 'streaming'"), v.message());
        assertTrue(v.message().contains("duplicate Feature name 'MPL'"), v.message());
    }

    @Test
    @DisplayName("an override naming the run's own language is rejected (Req 4.7)")
    void overrideOfOwnLanguageIsRejected() {
        ConfigurationSetValidation v = ConfigurationValidation.validate(
            set(entry("java", 8091), entry("python", 8092)),
            List.of(entry("java", 8091)),
            "java");
        assertFalse(v.valid());
        assertTrue(v.message().contains("own language"), v.message());
        assertTrue(v.message().contains("working tree"), v.message());
        assertTrue(v.message().contains("java"), v.message());
    }

    @Test
    @DisplayName("an override naming a language with no commons-stored entry is rejected (Req 4.11)")
    void overrideOfUnknownLanguageIsRejected() {
        ConfigurationSetValidation v = ConfigurationValidation.validate(
            set(entry("java", 8091)),
            List.of(entry("rust", 8093)),
            "java");
        assertFalse(v.valid());
        assertTrue(v.message().contains("no commons-stored Configuration_Entry"), v.message());
        assertTrue(v.message().contains("rust"), v.message());
    }

    @Test
    @DisplayName("an override is validated structurally like a commons entry (Req 4.6)")
    void overrideIsStructurallyValidated() {
        ConfigurationEntry incompleteOverride = new ConfigurationEntry("python", 4, 8092,
            new RepositoryCoordinates("repo-python", "url", "branch", "."),
            new ServerLocation("aws-crypto-tools-commons", "url", "ref", null), // missing path
            null, null);
        ConfigurationSetValidation v = ConfigurationValidation.validate(
            set(entry("java", 8091), entry("python", 8092)),
            List.of(incompleteOverride),
            "java");
        assertFalse(v.valid());
        assertTrue(v.message().contains("override python: serverLocation missing path"), v.message());
    }

    @Test
    @DisplayName("port uniqueness is checked across the effective set (Req 3.2)")
    void portUniquenessUsesTheEffectiveSet() {
        // The override moves python onto java's port: the effective set collides.
        ConfigurationEntry collidingOverride = entry("python", 8091);
        ConfigurationSetValidation collision = ConfigurationValidation.validate(
            set(entry("java", 8091), entry("python", 8092)),
            List.of(collidingOverride),
            "java");
        assertFalse(collision.valid());
        assertTrue(collision.message().contains("share port 8091"), collision.message());

        // Conversely: commons entries collide, but the override resolves it.
        ConfigurationSetValidation resolved = ConfigurationValidation.validate(
            set(entry("java", 8091), entry("python", 8091)),
            List.of(entry("python", 8092)),
            "java");
        assertTrue(resolved.valid(), "expected the override to resolve the collision: "
            + resolved.errors());
    }
}
