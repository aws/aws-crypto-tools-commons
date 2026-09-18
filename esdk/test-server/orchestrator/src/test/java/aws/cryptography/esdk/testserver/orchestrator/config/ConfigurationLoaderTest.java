package aws.cryptography.esdk.testserver.orchestrator.config;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Unit tests for {@link ConfigurationLoader}: strict parsing of the two
 * configuration file kinds (the Configuration_Set and a Language_Repository's
 * commons-configuration file), duplicate-key rejection
 * ({@code STRICT_DUPLICATE_DETECTION}), and missing/unparseable-file errors that
 * name the expected location.
 */
class ConfigurationLoaderTest {

    // ------------------------------------------------------------------
    // Configuration_Set parsing
    // ------------------------------------------------------------------

    @Test
    @DisplayName("parses the design-schema Configuration_Set: product, Feature_Catalog, entries")
    void parsesDesignSchemaConfigurationSet() {
        ConfigurationSet set = ConfigurationLoader.parseConfigurationSet("""
            {
              "product": "esdk",
              "features": ["streaming", "MPL"],
              "entries": [
                {
                  "language": "java",
                  "majorVersion": 3,
                  "port": 8091,
                  "libraryRepository": {
                    "name": "aws-crypto-tools-java",
                    "url": "git@github.com:aws/aws-crypto-tools-java.git",
                    "branch": "main",
                    "path": "esdk"
                  },
                  "serverLocation": {
                    "repository": "aws-crypto-tools-java",
                    "url": "git@github.com:aws/aws-crypto-tools-java.git",
                    "ref": "main",
                    "path": "esdk/test-server/server"
                  }
                },
                {
                  "language": "python",
                  "majorVersion": 4,
                  "port": 8092,
                  "supportedFeatures": ["streaming", "MPL"],
                  "unsupportedFeatures": [],
                  "libraryRepository": {
                    "name": "aws-encryption-sdk-python",
                    "url": "https://github.com/aws/aws-encryption-sdk-python",
                    "branch": "master"
                  },
                  "serverLocation": {
                    "repository": "aws-crypto-tools-commons",
                    "url": "git@github.com:aws/aws-crypto-tools-commons.git",
                    "ref": "main",
                    "path": "esdk/test-server/servers/python"
                  }
                }
              ]
            }
            """);

        assertEquals("esdk", set.product());
        assertEquals(List.of("streaming", "MPL"), set.features());
        assertEquals(2, set.entries().size());

        ConfigurationEntry java = set.forLanguage("java");
        assertNotNull(java);
        assertEquals(3, java.majorVersion());
        assertEquals(8091, java.port());
        assertEquals("aws-crypto-tools-java", java.libraryRepository().name());
        assertEquals("esdk", java.libraryRepository().path());
        assertEquals("esdk/test-server/server", java.serverLocation().path());
        assertNull(java.supportedFeatures(), "java carries no Feature_Declaration in the set");
        assertNull(java.unsupportedFeatures());
        // Legacy accessors are derived from the libraryRepository object.
        assertEquals("main", java.branch());
        assertEquals("aws-crypto-tools-java", java.repository());

        ConfigurationEntry python = set.forLanguage("python");
        assertNotNull(python);
        assertEquals(List.of("streaming", "MPL"), python.supportedFeatures());
        assertEquals(List.of(), python.unsupportedFeatures());
        assertTrue(python.hasFeatureDeclaration());
        // An omitted libraryRepository.path defaults to "." (design "Data Models").
        assertEquals(".", python.libraryRepository().path());
        assertEquals("aws-crypto-tools-commons", python.serverLocation().repository());
    }

    @Test
    @DisplayName("missing fields parse as null for validation to reject, not as parse errors")
    void missingFieldsParseAsNull() {
        ConfigurationSet set = ConfigurationLoader.parseConfigurationSet(
            "{ \"entries\": [ { \"language\": \"java\" } ] }");

        assertNull(set.product());
        assertNull(set.features());
        ConfigurationEntry entry = set.entries().get(0);
        assertNull(entry.majorVersion());
        assertNull(entry.port());
        assertNull(entry.libraryRepository());
        assertNull(entry.serverLocation());
        assertNull(entry.supportedFeatures());
        assertNull(entry.rawRsaPaddingSchemes());
    }

    // ------------------------------------------------------------------
    // Commons-configuration parsing
    // ------------------------------------------------------------------

    @Test
    @DisplayName("parses the commons-configuration file: entry, product, declaration, overrides")
    void parsesCommonsConfiguration() {
        CommonsConfiguration config = ConfigurationLoader.parseCommonsConfiguration("""
            {
              "commonsRepository": {
                "name": "aws-crypto-tools-commons",
                "url": "git@github.com:aws/aws-crypto-tools-commons.git",
                "branch": "kessplas/esdk-test-server"
              },
              "product": "esdk",
              "supportedFeatures": ["streaming", "MPL"],
              "unsupportedFeatures": [],
              "configurationOverrides": [
                {
                  "language": "python",
                  "majorVersion": 4,
                  "port": 8092,
                  "libraryRepository": {
                    "name": "aws-encryption-sdk-python",
                    "url": "https://github.com/aws/aws-encryption-sdk-python",
                    "branch": "some-feature-branch"
                  },
                  "serverLocation": {
                    "repository": "aws-crypto-tools-commons",
                    "url": "git@github.com:aws/aws-crypto-tools-commons.git",
                    "ref": "some-feature-branch",
                    "path": "esdk/test-server/servers/python"
                  }
                }
              ]
            }
            """);

        assertEquals("aws-crypto-tools-commons", config.commonsRepository().name());
        assertEquals("kessplas/esdk-test-server", config.commonsRepository().branch());
        assertEquals("esdk", config.product());
        assertEquals(List.of("streaming", "MPL"), config.supportedFeatures());
        assertEquals(List.of(), config.unsupportedFeatures());
        assertNull(config.rawRsaPaddingSchemes());
        assertEquals(1, config.configurationOverrides().size());
        ConfigurationEntry override = config.configurationOverrides().get(0);
        assertEquals("python", override.language());
        assertEquals("some-feature-branch", override.serverLocation().ref());
    }

    @Test
    @DisplayName("absent configurationOverrides defaults to an empty list")
    void absentOverridesDefaultToEmpty() {
        CommonsConfiguration config = ConfigurationLoader.parseCommonsConfiguration(
            "{ \"product\": \"esdk\" }");
        assertEquals(List.of(), config.configurationOverrides());
        assertNull(config.commonsRepository());
        assertNull(config.supportedFeatures());
    }

    @Test
    @DisplayName("parses an entry's configPath (the server's config directory)")
    void parsesEntryConfigPath() {
        ConfigurationSet set = ConfigurationLoader.parseConfigurationSet("""
            {
              "product": "esdk",
              "features": ["raw-aes"],
              "entries": [
                { "language": "rust", "majorVersion": 1, "port": 8093,
                  "configPath": "esdk-test-server" }
              ]
            }
            """);
        assertEquals("esdk-test-server", set.entries().get(0).configPath());
    }

    // ------------------------------------------------------------------
    // Strict duplicate detection (both file kinds)
    // ------------------------------------------------------------------

    @Test
    @DisplayName("rawRsaPaddingSchemes parses in both Feature_Declaration carriers")
    void parsesRawRsaPaddingSchemes() {
        CommonsConfiguration carried = ConfigurationLoader.parseCommonsConfiguration("""
            {
              "product": "esdk",
              "supportedFeatures": ["raw-rsa"],
              "unsupportedFeatures": [],
              "rawRsaPaddingSchemes": ["PKCS1", "OAEP_SHA1_MGF1", "OAEP_SHA256_MGF1"]
            }
            """);
        assertEquals(List.of("PKCS1", "OAEP_SHA1_MGF1", "OAEP_SHA256_MGF1"),
            carried.rawRsaPaddingSchemes());

        ConfigurationSet set = ConfigurationLoader.parseConfigurationSet("""
            { "entries": [ { "language": "python",
                             "rawRsaPaddingSchemes": ["PKCS1"] } ] }
            """);
        assertEquals(List.of("PKCS1"), set.entries().get(0).rawRsaPaddingSchemes());
    }

    @Test
    @DisplayName("a duplicate JSON key in the Configuration_Set is an unparseable-file error")
    void duplicateKeyInConfigurationSetIsRejected() {
        ConfigurationLoadException e = assertThrows(ConfigurationLoadException.class,
            () -> ConfigurationLoader.parseConfigurationSet(
                "{ \"product\": \"esdk\", \"product\": \"other\", \"entries\": [] }"));
        assertTrue(e.getMessage().contains("unparseable"),
            "duplicate keys must be reported as unparseable: " + e.getMessage());
    }

    @Test
    @DisplayName("a duplicate JSON key in the commons-configuration file is rejected, however nested")
    void duplicateKeyInCommonsConfigurationIsRejected() {
        assertThrows(ConfigurationLoadException.class,
            () -> ConfigurationLoader.parseCommonsConfiguration("""
                {
                  "commonsRepository": { "name": "a", "name": "b" },
                  "product": "esdk"
                }
                """));
    }

    // ------------------------------------------------------------------
    // Missing / unparseable files name the expected location
    // ------------------------------------------------------------------

    @Test
    @DisplayName("a missing Configuration_Set file names the expected location")
    void missingConfigurationSetNamesExpectedLocation(@TempDir Path dir) {
        Path configDir = dir.resolve("config");
        Path expected = configDir.resolve("server-config.json");
        ConfigurationLoadException e = assertThrows(ConfigurationLoadException.class,
            () -> ConfigurationLoader.loadConfigurationSet(configDir));
        assertTrue(e.getMessage().contains(expected.toString()),
            "the error must name the expected location: " + e.getMessage());
        assertEquals(expected, e.expectedLocation());
    }

    @Test
    @DisplayName("a missing commons-configuration file names the expected location (Req 4.9)")
    void missingCommonsConfigurationNamesExpectedLocation(@TempDir Path dir) {
        Path expected = dir.resolve("server-config.json");
        ConfigurationLoadException e = assertThrows(ConfigurationLoadException.class,
            () -> ConfigurationLoader.loadCommonsConfiguration(dir));
        assertTrue(e.getMessage().contains(expected.toString()));
    }

    @Test
    @DisplayName("malformed JSON names the expected location and the cause")
    void malformedJsonNamesExpectedLocation(@TempDir Path dir) throws Exception {
        Path file = dir.resolve("server-config.json");
        Files.writeString(file, "{ not json");
        ConfigurationLoadException e = assertThrows(ConfigurationLoadException.class,
            () -> ConfigurationLoader.loadConfigurationSet(dir));
        assertTrue(e.getMessage().contains(file.toString()));
        assertTrue(e.getMessage().contains("unparseable"));
    }

    @Test
    @DisplayName("a non-object top level is an unparseable-file error")
    void nonObjectTopLevelIsRejected() {
        assertThrows(ConfigurationLoadException.class,
            () -> ConfigurationLoader.parseConfigurationSet("[1, 2, 3]"));
    }

    // ------------------------------------------------------------------
    // The shipped, relocated Configuration_Set
    // ------------------------------------------------------------------

    @Test
    @DisplayName("the shipped config/ parses to the design schema (Req 1.3, 7.1, 7.3, 8.13)")
    void shippedConfigurationSetParses() {
        // The TestServer-level home: esdk/test-server/config/, a sibling of the
        // orchestrator module (the Gradle test working directory).
        Path shipped = Path.of("..", "config").toAbsolutePath().normalize();
        ConfigurationSet set = ConfigurationLoader.loadConfigurationSet(shipped);

        assertEquals("esdk", set.product());
        assertEquals(List.of(
            "streaming", "MPL", "hierarchical",
            "raw-aes", "raw-rsa", "raw-ecdh", "multi",
            "aws-kms", "aws-kms-multi", "aws-kms-discovery",
            "aws-kms-mrk", "aws-kms-mrk-multi", "aws-kms-mrk-discovery",
            "aws-kms-rsa", "aws-kms-ecdh",
            "required-encryption-context", "caching"), set.features());

        ConfigurationEntry java = set.forLanguage("java");
        assertNotNull(java, "the shipped set must carry a java entry");
        assertEquals(3, java.majorVersion());
        assertEquals(8091, java.port());
        // The Java server is hosted in aws-encryption-sdk-java.
        assertEquals("aws-encryption-sdk-java", java.serverLocation().repository());
        assertEquals("test-server/server", java.serverLocation().path());

        ConfigurationEntry python = set.forLanguage("python");
        assertNotNull(python, "the shipped set must carry a python entry");
        assertEquals(4, python.majorVersion());
        assertEquals(8092, python.port());
        // Python's Feature_Declaration and bugs live in its own
        // feature-config.json / bug-config.json in its repository, so the entry
        // carries no inline arrays. The server now lives in the
        // aws-encryption-sdk-python Language_Repository under test-server/.
        assertNull(python.supportedFeatures());
        assertNull(python.unsupportedFeatures());
        assertEquals("test-server", python.configPath());
        assertEquals("aws-encryption-sdk-python", python.serverLocation().repository());
        assertEquals("test-server", python.serverLocation().path());

        // Rust is a Language_Repository (aws-crypto-tools-rust): its
        // Feature_Declaration lives in its own repo, not inline here, so the entry
        // carries no supported/unsupported arrays and points at its declaration
        // location, alongside its server sources under esdk-test-server/.
        ConfigurationEntry rust = set.forLanguage("rust");
        assertNotNull(rust, "the shipped set must carry a rust entry");
        assertEquals(1, rust.majorVersion());
        assertEquals(8093, rust.port());
        assertEquals("aws-crypto-tools-rust", rust.serverLocation().repository());
        assertEquals("esdk-test-server", rust.serverLocation().path());
        assertEquals("esdk-test-server", rust.configPath());
        assertNull(rust.supportedFeatures());
        assertNull(rust.unsupportedFeatures());

        // The remaining entries follow the same Language_Repository pattern:
        // no inline arrays, a configPath directory next to the server.
        assertLanguageRepositoryEntry(set, "rust-cpp", 1, 8094,
            "aws-crypto-tools-rust-cpp", "esdk-cpp-test-server",
            "esdk-cpp-test-server");
        assertLanguageRepositoryEntry(set, "javascript", 5, 8095,
            "aws-encryption-sdk-javascript", "test-server",
            "test-server");
        assertLanguageRepositoryEntry(set, "c", 2, 8096,
            "aws-encryption-sdk-c", "test-server",
            "test-server");
        assertLanguageRepositoryEntry(set, "net", 5, 8097,
            "aws-encryption-sdk", "esdk-test-servers/net",
            "esdk-test-servers/net");
        assertLanguageRepositoryEntry(set, "rust-dafny", 1, 8098,
            "aws-encryption-sdk", "esdk-test-servers/rust",
            "esdk-test-servers/rust");
        assertLanguageRepositoryEntry(set, "go", 1, 8099,
            "aws-encryption-sdk", "esdk-test-servers/go",
            "esdk-test-servers/go");
    }

    @Test
    @DisplayName("the shipped bug ledger loads as a catalog of {id, description, ticketId}")
    void shippedBugLedgerLoads() {
        Path shipped = Path.of("..", "config").toAbsolutePath().normalize();
        ConfigurationSet set = ConfigurationLoader.loadConfigurationSet(shipped);
        assertTrue(!set.bugLedger().isEmpty(), "the shipped bug ledger must be populated");
        BugLedgerEntry bug = set.bugLedger().stream()
            .filter(b -> "encrypt-non-positive-frame-length-generic-error".equals(b.id()))
            .findFirst().orElseThrow();
        assertTrue(bug.description() != null && !bug.description().isBlank(),
            "ledger entries carry a description");
        assertNull(bug.ticketId(), "ticketId is null until a ticket is filed");
    }

    @Test
    @DisplayName("local-overrides overlay parses repositories, resolving relative paths against the file")
    void localOverridesOverlayParses(@TempDir Path dir) throws Exception {
        Path file = dir.resolve("local-overrides.json");
        Files.writeString(file,
            "{ \"repositories\": { \"rust\": \"/abs/rust\", \"java\": \"checkouts/java\" } }");

        Map<String, Path> repos = ConfigurationLoader.loadLocalRepositories(file);

        assertEquals(Path.of("/abs/rust"), repos.get("rust"),
            "an absolute path is used as-is");
        assertEquals(dir.resolve("checkouts/java").normalize(), repos.get("java"),
            "a relative path resolves against the overlay file's directory");
    }

    @Test
    @DisplayName("a local-overrides overlay with no repositories object yields an empty map")
    void localOverridesOverlayEmptyWhenNoRepositories(@TempDir Path dir) throws Exception {
        Path file = dir.resolve("local-overrides.json");
        Files.writeString(file, "{ }");
        assertTrue(ConfigurationLoader.loadLocalRepositories(file).isEmpty());
    }

    /**
     * Assert one shipped Language_Repository-pattern entry: its coordinates,
     * its config directory, and that no inline Feature_Declaration is carried.
     */
    private static void assertLanguageRepositoryEntry(ConfigurationSet set, String language,
            int majorVersion, int port, String serverRepository, String serverPath,
            String configPath) {
        ConfigurationEntry entry = set.forLanguage(language);
        assertNotNull(entry, "the shipped set must carry a " + language + " entry");
        assertEquals(majorVersion, entry.majorVersion(), language + " majorVersion");
        assertEquals(port, entry.port(), language + " port");
        assertEquals(serverRepository, entry.serverLocation().repository(),
            language + " serverLocation.repository");
        assertEquals(serverPath, entry.serverLocation().path(),
            language + " serverLocation.path");
        assertEquals(configPath, entry.configPath(), language + " configPath");
        assertNull(entry.supportedFeatures(), language + " carries no inline supportedFeatures");
        assertNull(entry.unsupportedFeatures(), language + " carries no inline unsupportedFeatures");
    }
}
