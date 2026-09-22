package aws.cryptography.testserver.orchestrator.config;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Unit tests for {@link ConfigurationLoader}: strict parsing of the three-file
 * configuration — the commons trio ({@code server-config.json} +
 * {@code feature-set.json} + {@code bug-list.json}) and a Language_Repository's
 * per-server trio ({@code server-config.json} + {@code feature-config.json} +
 * {@code bug-config.json}) — duplicate-key rejection
 * ({@code STRICT_DUPLICATE_DETECTION}), and missing/unparseable-file errors that
 * name the expected location.
 */
class ConfigurationLoaderTest {

    private static void write(Path dir, String name, String json) {
        try {
            Files.writeString(dir.resolve(name), json);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    private static Path subDir(Path parent, String name) {
        try {
            return Files.createDirectories(parent.resolve(name));
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    // ------------------------------------------------------------------
    // Commons trio parsing (server-config.json + feature-set.json)
    // ------------------------------------------------------------------

    @Test
    @DisplayName("parses the commons trio: product, Feature_Catalog, entries")
    void parsesCommonsTrio(@TempDir Path dir) {
        write(dir, "server-config.json", """
            {
              "product": "esdk",
              "entries": [
                {
                  "language": "java",
                  "majorVersion": 3,
                  "port": 8091,
                  "libraryRepository": {
                    "name": "aws-database-encryption-sdk-dynamodb",
                    "url": "git@github.com:aws/aws-database-encryption-sdk-dynamodb.git",
                    "branch": "main",
                    "path": "esdk"
                  },
                  "serverLocation": {
                    "repository": "aws-database-encryption-sdk-dynamodb",
                    "url": "git@github.com:aws/aws-database-encryption-sdk-dynamodb.git",
                    "ref": "main",
                    "path": "dbesdk/test-server/server"
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
                    "path": "dbesdk/test-server/servers/python"
                  }
                }
              ]
            }
            """);
        write(dir, "feature-set.json", "{ \"features\": [\"streaming\", \"MPL\"] }");

        CommonsConfiguration set = ConfigurationLoader.loadCommonsConfiguration(dir);

        assertEquals("esdk", set.product());
        assertEquals(List.of("streaming", "MPL"), set.features());
        assertEquals(2, set.entries().size());

        ConfigurationEntry java = set.forLanguage("java");
        assertNotNull(java);
        assertEquals(3, java.majorVersion());
        assertEquals(8091, java.port());
        assertEquals("aws-database-encryption-sdk-dynamodb", java.libraryRepository().name());
        assertEquals("esdk", java.libraryRepository().path());
        assertEquals("dbesdk/test-server/server", java.serverLocation().path());
        assertNull(java.supportedFeatures(), "java carries no Feature_Declaration in the set");
        assertNull(java.unsupportedFeatures());
        // Legacy accessors are derived from the libraryRepository object.
        assertEquals("main", java.branch());
        assertEquals("aws-database-encryption-sdk-dynamodb", java.repository());

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
    void missingFieldsParseAsNull(@TempDir Path dir) {
        write(dir, "server-config.json", "{ \"entries\": [ { \"language\": \"java\" } ] }");
        write(dir, "feature-set.json", "{}");

        CommonsConfiguration set = ConfigurationLoader.loadCommonsConfiguration(dir);

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
    // Per-server trio parsing (server-config.json + feature-config.json)
    // ------------------------------------------------------------------

    @Test
    @DisplayName("parses the per-server trio: repository, product, declaration, overrides")
    void parsesPerServerTrio(@TempDir Path dir) {
        write(dir, "server-config.json", """
            {
              "commonsRepository": {
                "name": "aws-crypto-tools-commons",
                "url": "git@github.com:aws/aws-crypto-tools-commons.git",
                "branch": "kessplas/esdk-test-server"
              },
              "product": "esdk",
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
                    "path": "dbesdk/test-server/servers/python"
                  }
                }
              ]
            }
            """);
        write(dir, "feature-config.json",
            "{ \"supportedFeatures\": [\"streaming\", \"MPL\"], \"unsupportedFeatures\": [] }");

        ServerConfiguration config = ConfigurationLoader.loadServerConfiguration(dir);

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
    void absentOverridesDefaultToEmpty(@TempDir Path dir) {
        write(dir, "server-config.json", "{ \"product\": \"esdk\" }");
        write(dir, "feature-config.json", "{}");
        ServerConfiguration config = ConfigurationLoader.loadServerConfiguration(dir);
        assertEquals(List.of(), config.configurationOverrides());
        assertNull(config.commonsRepository());
        assertNull(config.supportedFeatures());
    }

    @Test
    @DisplayName("rawRsaPaddingSchemes parses in both Feature_Declaration carriers")
    void parsesRawRsaPaddingSchemes(@TempDir Path dir) {
        Path perServer = subDir(dir, "per-server");
        write(perServer, "server-config.json", "{ \"product\": \"esdk\" }");
        write(perServer, "feature-config.json", """
            {
              "supportedFeatures": ["raw-rsa"],
              "unsupportedFeatures": [],
              "rawRsaPaddingSchemes": ["PKCS1", "OAEP_SHA1_MGF1", "OAEP_SHA256_MGF1"]
            }
            """);
        ServerConfiguration carried = ConfigurationLoader.loadServerConfiguration(perServer);
        assertEquals(List.of("PKCS1", "OAEP_SHA1_MGF1", "OAEP_SHA256_MGF1"),
            carried.rawRsaPaddingSchemes());

        Path commons = subDir(dir, "commons");
        write(commons, "server-config.json", """
            { "entries": [ { "language": "python",
                             "rawRsaPaddingSchemes": ["PKCS1"] } ] }
            """);
        write(commons, "feature-set.json", "{}");
        CommonsConfiguration set = ConfigurationLoader.loadCommonsConfiguration(commons);
        assertEquals(List.of("PKCS1"), set.entries().get(0).rawRsaPaddingSchemes());
    }

    // ------------------------------------------------------------------
    // Strict duplicate detection (both trios)
    // ------------------------------------------------------------------

    @Test
    @DisplayName("a duplicate JSON key in server-config.json is an unparseable-file error")
    void duplicateKeyInServerConfigIsRejected(@TempDir Path dir) {
        write(dir, "server-config.json",
            "{ \"product\": \"esdk\", \"product\": \"other\", \"entries\": [] }");
        write(dir, "feature-set.json", "{}");
        ConfigurationLoadException e = assertThrows(ConfigurationLoadException.class,
            () -> ConfigurationLoader.loadCommonsConfiguration(dir));
        assertTrue(e.getMessage().contains("unparseable"),
            "duplicate keys must be reported as unparseable: " + e.getMessage());
    }

    @Test
    @DisplayName("a duplicate JSON key in the per-server server-config.json is rejected, however nested")
    void duplicateKeyInPerServerConfigIsRejected(@TempDir Path dir) {
        write(dir, "server-config.json", """
            {
              "commonsRepository": { "name": "a", "name": "b" },
              "product": "esdk"
            }
            """);
        write(dir, "feature-config.json", "{}");
        assertThrows(ConfigurationLoadException.class,
            () -> ConfigurationLoader.loadServerConfiguration(dir));
    }

    // ------------------------------------------------------------------
    // Missing / unparseable files name the expected location
    // ------------------------------------------------------------------

    @Test
    @DisplayName("a missing commons server-config.json names the expected location")
    void missingServerConfigNamesExpectedLocation(@TempDir Path dir) {
        Path expected = dir.resolve("server-config.json");
        ConfigurationLoadException e = assertThrows(ConfigurationLoadException.class,
            () -> ConfigurationLoader.loadCommonsConfiguration(dir));
        assertTrue(e.getMessage().contains(expected.toString()),
            "the error must name the expected location: " + e.getMessage());
        assertEquals(expected, e.expectedLocation());
    }

    @Test
    @DisplayName("a missing per-server server-config.json names the expected location (Req 4.9)")
    void missingPerServerConfigNamesExpectedLocation(@TempDir Path dir) {
        Path expected = dir.resolve("server-config.json");
        ConfigurationLoadException e = assertThrows(ConfigurationLoadException.class,
            () -> ConfigurationLoader.loadServerConfiguration(dir));
        assertTrue(e.getMessage().contains(expected.toString()));
    }

    @Test
    @DisplayName("a missing feature-set.json names the expected location")
    void missingFeatureSetNamesExpectedLocation(@TempDir Path dir) {
        write(dir, "server-config.json", "{ \"product\": \"esdk\", \"entries\": [] }");
        Path expected = dir.resolve("feature-set.json");
        ConfigurationLoadException e = assertThrows(ConfigurationLoadException.class,
            () -> ConfigurationLoader.loadCommonsConfiguration(dir));
        assertTrue(e.getMessage().contains(expected.toString()),
            "the error must name the expected location: " + e.getMessage());
    }

    @Test
    @DisplayName("malformed JSON names the expected location and the cause")
    void malformedJsonNamesExpectedLocation(@TempDir Path dir) {
        write(dir, "server-config.json", "{ not json");
        write(dir, "feature-set.json", "{}");
        Path expected = dir.resolve("server-config.json");
        ConfigurationLoadException e = assertThrows(ConfigurationLoadException.class,
            () -> ConfigurationLoader.loadCommonsConfiguration(dir));
        assertTrue(e.getMessage().contains(expected.toString()));
        assertTrue(e.getMessage().contains("unparseable"));
    }

    @Test
    @DisplayName("a non-object top level is an unparseable-file error")
    void nonObjectTopLevelIsRejected(@TempDir Path dir) {
        write(dir, "server-config.json", "[1, 2, 3]");
        write(dir, "feature-set.json", "{}");
        assertThrows(ConfigurationLoadException.class,
            () -> ConfigurationLoader.loadCommonsConfiguration(dir));
    }
}
