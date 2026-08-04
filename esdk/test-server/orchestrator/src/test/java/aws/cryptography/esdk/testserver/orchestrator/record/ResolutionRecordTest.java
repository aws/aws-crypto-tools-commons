package aws.cryptography.esdk.testserver.orchestrator.record;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import aws.cryptography.esdk.testserver.orchestrator.source.CommonsOrigin;
import aws.cryptography.esdk.testserver.orchestrator.source.ComponentId;
import aws.cryptography.esdk.testserver.orchestrator.source.MaterializedSources;
import aws.cryptography.esdk.testserver.orchestrator.source.ResolutionReason;
import aws.cryptography.esdk.testserver.orchestrator.source.RunContext;
import aws.cryptography.esdk.testserver.orchestrator.source.SourcePlan;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Unit tests for the Resolution_Record: assembly from mixed materialization
 * outcomes, the run-gating completeness check, the JSON document shape, and the
 * readable stdout block. The exhaustive generated-outcome coverage is Property 5.
 */
class ResolutionRecordTest {

    private static final String COMMONS_URL =
        "https://github.com/aws/aws-crypto-tools-commons.git";
    private static final String PYTHON_URL =
        "git@github.com:aws/aws-encryption-sdk-python.git";
    private static final String JAVA_URL =
        "https://github.com/aws/aws-crypto-tools-java.git";
    private static final String BRANCH = "kessplas/esdk-test-server";

    // ------------------------------------------------------------------
    // Fixtures
    // ------------------------------------------------------------------

    private static RunContext languageContext() {
        return RunContext.languageRun(
            "java",
            Path.of("/work/aws-crypto-tools-java"),
            Path.of("/work/aws-crypto-tools-java/.commons-clone"),
            "aws-crypto-tools-java",
            new CommonsOrigin(COMMONS_URL, BRANCH, ResolutionReason.CONFIGURATION_ENTRY));
    }

    private static RunContext commonsContext() {
        return RunContext.commonsRun(
            Path.of("/work/aws-crypto-tools-commons"), "aws-crypto-tools-commons");
    }

    /**
     * A Language_Repository_Run's mixed outcomes: commons clone success, own
     * java library + server from the (dirty) working tree, python library
     * clone success, python server clone failure.
     */
    private static MaterializedSources mixedLanguageRunSources() {
        var commonsClone = new SourcePlan.Clone(COMMONS_URL, BRANCH, ".");
        var javaLibraryTree = new SourcePlan.WorkingTree(
            Path.of("/work/aws-crypto-tools-java"), ".");
        var javaServerTree = new SourcePlan.WorkingTree(
            Path.of("/work/aws-crypto-tools-java"), "esdk/test-server/server");
        var pythonLibraryClone = new SourcePlan.Clone(PYTHON_URL, "master", ".");
        var pythonServerClone = new SourcePlan.Clone(
            COMMONS_URL, BRANCH, "esdk/test-server/servers/python");
        return new MaterializedSources(List.of(
            new MaterializedSources.Success(ComponentId.commons(), commonsClone,
                ResolutionReason.CONFIGURATION_ENTRY,
                Path.of("/scratch/commons"), "0a1b2c", BRANCH, null),
            new MaterializedSources.Success(ComponentId.library("java"), javaLibraryTree,
                ResolutionReason.WORKING_TREE,
                Path.of("/work/aws-crypto-tools-java"), "3d4e5f", BRANCH, true),
            new MaterializedSources.Success(ComponentId.server("java"), javaServerTree,
                ResolutionReason.WORKING_TREE,
                Path.of("/work/aws-crypto-tools-java/esdk/test-server/server"),
                "3d4e5f", BRANCH, true),
            new MaterializedSources.Success(ComponentId.library("python"), pythonLibraryClone,
                ResolutionReason.CONFIGURATION_ENTRY,
                Path.of("/scratch/python"), "6a7b8c", "master", null),
            new MaterializedSources.Failure(ComponentId.server("python"), pythonServerClone,
                ResolutionReason.CONFIGURATION_ENTRY,
                "git clone failed for " + COMMONS_URL + " at branch " + BRANCH
                    + ": repository not found")));
    }

    // ------------------------------------------------------------------
    // Assembly
    // ------------------------------------------------------------------

    @Test
    @DisplayName("assembly maps every outcome: successes to components, failures to failures")
    void assemblyFromMixedOutcomes() {
        ResolutionRecord record =
            ResolutionRecord.assemble(languageContext(), mixedLanguageRunSources());

        assertEquals("language:java", record.runContext());
        assertEquals(RunContext.Kind.LANGUAGE, record.kind());
        assertEquals(List.of("commons", "library:java", "server:java", "library:python"),
            record.components().stream().map(ResolutionRecord.Component::component).toList());
        assertEquals(List.of("server:python"),
            record.failures().stream().map(ResolutionRecord.Failure::component).toList());
    }

    @Test
    @DisplayName("clone components report the repository name derived from the clone URL")
    void cloneComponentFields() {
        ResolutionRecord record =
            ResolutionRecord.assemble(languageContext(), mixedLanguageRunSources());

        ResolutionRecord.Component commons = record.components().get(0);
        assertEquals("aws-crypto-tools-commons", commons.repository());
        assertEquals(BRANCH, commons.reference());
        assertEquals("0a1b2c", commons.commit());
        assertEquals(ResolutionReason.CONFIGURATION_ENTRY, commons.reason());
        assertNull(commons.path(), "the commons component carries no path");
        assertNull(commons.dirty(), "clone components carry no dirty flag");

        ResolutionRecord.Component pythonLibrary = record.components().get(3);
        assertEquals("aws-encryption-sdk-python", pythonLibrary.repository(),
            "scp-style URLs also reduce to the repository name");
        assertNull(pythonLibrary.path(), "library components carry no path");
        assertNull(pythonLibrary.dirty());
    }

    @Test
    @DisplayName("working-tree components use the invoking repository name and carry dirty")
    void workingTreeComponentFields() {
        ResolutionRecord record =
            ResolutionRecord.assemble(languageContext(), mixedLanguageRunSources());

        ResolutionRecord.Component javaLibrary = record.components().get(1);
        assertEquals("aws-crypto-tools-java", javaLibrary.repository());
        assertEquals(ResolutionReason.WORKING_TREE, javaLibrary.reason());
        assertEquals(Boolean.TRUE, javaLibrary.dirty(), "Requirement 5.7");
        assertNull(javaLibrary.path());

        ResolutionRecord.Component javaServer = record.components().get(2);
        assertEquals("esdk/test-server/server", javaServer.path(),
            "server components record their path");
        assertEquals("3d4e5f", javaServer.commit(),
            "working trees record the checked-out commit (Requirement 5.7)");
        assertEquals(Boolean.TRUE, javaServer.dirty());
    }

    @Test
    @DisplayName("failures carry attempted coordinates (path for servers) and the cause")
    void failureFields() {
        ResolutionRecord record =
            ResolutionRecord.assemble(languageContext(), mixedLanguageRunSources());

        ResolutionRecord.Failure failure = record.failures().get(0);
        assertEquals("server:python", failure.component());
        assertEquals("aws-crypto-tools-commons", failure.repository());
        assertEquals(BRANCH, failure.reference());
        assertEquals("esdk/test-server/servers/python", failure.path());
        assertTrue(failure.cause().contains("repository not found"));
    }

    @Test
    @DisplayName("a non-server failure records no path; a working-tree failure has no reference")
    void nonServerWorkingTreeFailure() {
        var treePlan = new SourcePlan.WorkingTree(Path.of("/work/aws-crypto-tools-java"), ".");
        var sources = new MaterializedSources(List.of(
            new MaterializedSources.Failure(ComponentId.library("java"), treePlan,
                ResolutionReason.WORKING_TREE,
                "path . does not exist in working tree /work/aws-crypto-tools-java")));

        ResolutionRecord record = ResolutionRecord.assemble(languageContext(), sources);

        ResolutionRecord.Failure failure = record.failures().get(0);
        assertEquals("aws-crypto-tools-java", failure.repository(),
            "working-tree failures report the invoking repository name");
        assertNull(failure.reference(), "no reference was requested for a working tree");
        assertNull(failure.path(), "path is recorded for server components only");
    }

    @Test
    @DisplayName("a Commons_Run record is labeled 'commons'")
    void commonsRunLabel() {
        var sources = new MaterializedSources(List.of(
            new MaterializedSources.Success(ComponentId.library("python"),
                new SourcePlan.Clone(PYTHON_URL, "master", "."),
                ResolutionReason.CONFIGURATION_ENTRY,
                Path.of("/scratch/python"), "6a7b8c", "master", null)));

        ResolutionRecord record = ResolutionRecord.assemble(commonsContext(), sources);

        assertEquals("commons", record.runContext());
        assertEquals(RunContext.Kind.COMMONS, record.kind());
    }

    // ------------------------------------------------------------------
    // Completeness
    // ------------------------------------------------------------------

    @Test
    @DisplayName("a full record passes the completeness check")
    void completeRecordPasses() {
        ResolutionRecord record =
            ResolutionRecord.assemble(languageContext(), mixedLanguageRunSources());

        ResolutionRecord.Completeness completeness =
            record.completeness(Set.of("java", "python"));

        assertTrue(completeness.complete(), String.valueOf(completeness.problems()));
        assertTrue(completeness.problems().isEmpty());
    }

    @Test
    @DisplayName("every missing language component is named")
    void missingComponentsAreNamed() {
        // Only java's library materialized; java server, python library+server,
        // and the commons clone of this LANGUAGE run are all absent.
        var sources = new MaterializedSources(List.of(
            new MaterializedSources.Success(ComponentId.library("java"),
                new SourcePlan.WorkingTree(Path.of("/work/aws-crypto-tools-java"), "."),
                ResolutionReason.WORKING_TREE,
                Path.of("/work/aws-crypto-tools-java"), "3d4e5f", BRANCH, false)));
        ResolutionRecord record = ResolutionRecord.assemble(languageContext(), sources);

        ResolutionRecord.Completeness completeness =
            record.completeness(Set.of("java", "python"));

        assertFalse(completeness.complete());
        assertTrue(completeness.problems().contains("missing component: server:java"));
        assertTrue(completeness.problems().contains("missing component: library:python"));
        assertTrue(completeness.problems().contains("missing component: server:python"));
        assertTrue(completeness.problems().contains("missing component: commons"));
    }

    @Test
    @DisplayName("commons is expected on LANGUAGE runs only")
    void commonsPresenceIsContextDependent() {
        var commonsComponent = new ResolutionRecord.Component("commons",
            "aws-crypto-tools-commons", BRANCH, "0a1b2c",
            ResolutionReason.CONFIGURATION_ENTRY, null, null);
        var javaLibrary = new ResolutionRecord.Component("library:java",
            "aws-crypto-tools-java", "main", "3d4e5f",
            ResolutionReason.CONFIGURATION_ENTRY, null, null);
        var javaServer = new ResolutionRecord.Component("server:java",
            "aws-crypto-tools-java", "main", "3d4e5f",
            ResolutionReason.CONFIGURATION_ENTRY, "esdk/test-server/server", null);

        ResolutionRecord commonsRun = new ResolutionRecord(RunContext.Kind.COMMONS, "commons",
            List.of(commonsComponent, javaLibrary, javaServer), List.of());
        ResolutionRecord.Completeness unexpected = commonsRun.completeness(Set.of("java"));
        assertFalse(unexpected.complete());
        assertTrue(unexpected.problems()
            .contains("unexpected commons component in a Commons_Run"));

        ResolutionRecord commonsRunWithout = new ResolutionRecord(RunContext.Kind.COMMONS,
            "commons", List.of(javaLibrary, javaServer), List.of());
        assertTrue(commonsRunWithout.completeness(Set.of("java")).complete());
    }

    @Test
    @DisplayName("empty required elements are named per component")
    void emptyElementsAreNamed() {
        var blankCommit = new ResolutionRecord.Component("library:java",
            "aws-crypto-tools-java", "main", "  ",
            ResolutionReason.CONFIGURATION_ENTRY, null, null);
        var serverWithoutPath = new ResolutionRecord.Component("server:java",
            "aws-crypto-tools-java", "main", "3d4e5f",
            ResolutionReason.CONFIGURATION_ENTRY, null, null);
        var workingTreeWithoutDirty = new ResolutionRecord.Component("library:python",
            "aws-encryption-sdk-python", "master", "6a7b8c",
            ResolutionReason.WORKING_TREE, null, null);
        var failureWithoutCause = new ResolutionRecord.Failure("server:python",
            "aws-crypto-tools-commons", BRANCH, null, "");
        ResolutionRecord record = new ResolutionRecord(RunContext.Kind.COMMONS, "commons",
            List.of(blankCommit, serverWithoutPath, workingTreeWithoutDirty),
            List.of(failureWithoutCause));

        ResolutionRecord.Completeness completeness =
            record.completeness(Set.of("java", "python"));

        assertFalse(completeness.complete());
        assertTrue(completeness.problems().contains("library:java: missing commit"));
        assertTrue(completeness.problems().contains("server:java: missing path"));
        assertTrue(completeness.problems()
            .contains("library:python: working-tree component missing the dirty flag"));
        assertTrue(completeness.problems().contains("server:python (failure): missing cause"));
        assertTrue(completeness.problems().contains("server:python (failure): missing path"));
    }

    @Test
    @DisplayName("a duplicated component is a completeness problem")
    void duplicateComponentsAreNamed() {
        var entry = new ResolutionRecord.Component("library:java",
            "aws-crypto-tools-java", "main", "3d4e5f",
            ResolutionReason.CONFIGURATION_ENTRY, null, null);
        var server = new ResolutionRecord.Component("server:java",
            "aws-crypto-tools-java", "main", "3d4e5f",
            ResolutionReason.CONFIGURATION_ENTRY, "esdk/test-server/server", null);
        ResolutionRecord record = new ResolutionRecord(RunContext.Kind.COMMONS, "commons",
            List.of(entry, entry, server), List.of());

        ResolutionRecord.Completeness completeness = record.completeness(Set.of("java"));

        assertFalse(completeness.complete());
        assertTrue(completeness.problems().contains("component recorded 2 times: library:java"));
    }

    // ------------------------------------------------------------------
    // JSON emission (design "Resolution_Record" document)
    // ------------------------------------------------------------------

    @Test
    @DisplayName("the JSON document matches the design shape")
    void jsonShape() throws Exception {
        ResolutionRecord record =
            ResolutionRecord.assemble(languageContext(), mixedLanguageRunSources());

        JsonNode root = new ObjectMapper().readTree(record.toJson());

        assertEquals("language:java", root.get("runContext").asText());
        assertEquals(4, root.get("components").size());
        assertEquals(1, root.get("failures").size());

        JsonNode commons = root.get("components").get(0);
        assertEquals("commons", commons.get("component").asText());
        assertEquals("aws-crypto-tools-commons", commons.get("repository").asText());
        assertEquals(BRANCH, commons.get("reference").asText());
        assertEquals("0a1b2c", commons.get("commit").asText());
        assertEquals("configuration-entry", commons.get("reason").asText());
        assertFalse(commons.has("path"), "no path outside server components");
        assertFalse(commons.has("dirty"), "no dirty flag on clone components");

        JsonNode javaServer = root.get("components").get(2);
        assertEquals("server:java", javaServer.get("component").asText());
        assertEquals("esdk/test-server/server", javaServer.get("path").asText());
        assertEquals("working-tree", javaServer.get("reason").asText());
        assertTrue(javaServer.get("dirty").asBoolean());

        JsonNode failure = root.get("failures").get(0);
        assertEquals("server:python", failure.get("component").asText());
        assertEquals("aws-crypto-tools-commons", failure.get("repository").asText());
        assertEquals(BRANCH, failure.get("reference").asText());
        assertEquals("esdk/test-server/servers/python", failure.get("path").asText());
        assertTrue(failure.get("cause").asText().contains("repository not found"));
    }

    @Test
    @DisplayName("writeJson creates parent directories and writes the document")
    void writeJsonToPath(@TempDir Path tempDir) throws Exception {
        ResolutionRecord record =
            ResolutionRecord.assemble(languageContext(), mixedLanguageRunSources());
        Path target = tempDir.resolve("orchestrator/build/resolution-record.json");

        record.writeJson(target);

        assertTrue(Files.exists(target));
        JsonNode root = new ObjectMapper().readTree(Files.readString(target));
        assertEquals("language:java", root.get("runContext").asText());
        assertEquals(4, root.get("components").size());
    }

    // ------------------------------------------------------------------
    // Stdout block
    // ------------------------------------------------------------------

    @Test
    @DisplayName("the stdout block names every component, its coordinates, and every failure")
    void stdoutBlockContent() {
        ResolutionRecord record =
            ResolutionRecord.assemble(languageContext(), mixedLanguageRunSources());

        String block = record.toStdoutBlock();

        assertTrue(block.contains("runContext: language:java"));
        assertTrue(block.contains("commons  repository=aws-crypto-tools-commons"
            + "  reference=" + BRANCH + "  commit=0a1b2c  reason=configuration-entry"));
        assertTrue(block.contains("server:java  repository=aws-crypto-tools-java"),
            block);
        assertTrue(block.contains("path=esdk/test-server/server"));
        assertTrue(block.contains("reason=working-tree  dirty=true"));
        assertTrue(block.contains("server:python  repository=aws-crypto-tools-commons"));
        assertTrue(block.contains("cause: git clone failed for " + COMMONS_URL));
    }

    @Test
    @DisplayName("an empty record still renders a readable block")
    void stdoutBlockEmptySections() {
        ResolutionRecord record = new ResolutionRecord(
            RunContext.Kind.COMMONS, "commons", List.of(), List.of());

        String block = record.toStdoutBlock();

        assertTrue(block.contains("resolved components: none"));
        assertTrue(block.contains("failures: none"));
    }

    // ------------------------------------------------------------------
    // Repository-name derivation (documented naming choice)
    // ------------------------------------------------------------------

    @Test
    @DisplayName("repository names derive from https, scp-style, and bare URLs")
    void repositoryNameDerivation() {
        assertEquals("aws-crypto-tools-java",
            ResolutionRecord.repositoryNameFromUrl(JAVA_URL));
        assertEquals("aws-encryption-sdk-python",
            ResolutionRecord.repositoryNameFromUrl(PYTHON_URL));
        assertEquals("aws-crypto-tools-commons",
            ResolutionRecord.repositoryNameFromUrl(
                "https://github.com/aws/aws-crypto-tools-commons/"));
        assertEquals("repo", ResolutionRecord.repositoryNameFromUrl("repo"));
    }
}
