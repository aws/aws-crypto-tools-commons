package aws.cryptography.testserver.orchestrator.source;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;

import aws.cryptography.testserver.orchestrator.config.ConfigurationEntry;
import aws.cryptography.testserver.orchestrator.config.CommonsConfiguration;
import aws.cryptography.testserver.orchestrator.config.RepositoryCoordinates;
import aws.cryptography.testserver.orchestrator.config.ServerLocation;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Example-based unit tests for the pure source-resolution planner (design
 * "Execution-context resolution rules" table) and commons-branch selection.
 * The exhaustive coverage lives in the jqwik property tests.
 */
class SourceResolverTest {

    private static final String COMMONS = "aws-crypto-tools-commons";
    private static final String JAVA_REPO = "aws-database-encryption-sdk-dynamodb";
    private static final Path COMMONS_ROOT = Path.of("/work/commons");
    private static final Path JAVA_ROOT = Path.of("/work/java-repo");

    private static ConfigurationEntry javaEntry() {
        return new ConfigurationEntry("java", 3, 8091,
            new RepositoryCoordinates(JAVA_REPO,
                "git@github.com:aws/aws-database-encryption-sdk-dynamodb.git", "main", "esdk"),
            new ServerLocation(JAVA_REPO,
                "git@github.com:aws/aws-database-encryption-sdk-dynamodb.git", "main",
                "dbesdk/test-server/server"),
            null, null);
    }

    private static ConfigurationEntry pythonEntry() {
        return new ConfigurationEntry("python", 4, 8092,
            new RepositoryCoordinates("aws-encryption-sdk-python",
                "https://github.com/aws/aws-encryption-sdk-python", "master", "."),
            new ServerLocation(COMMONS,
                "git@github.com:aws/aws-crypto-tools-commons.git", "main",
                "dbesdk/test-server/servers/python"),
            List.of("streaming", "MPL"), List.of());
    }

    private static CommonsConfiguration set() {
        return new CommonsConfiguration("esdk", List.of("streaming", "MPL"),
            List.of(javaEntry(), pythonEntry()));
    }

    private static Map<ComponentId, ResolvedComponentPlan> byComponent(
            List<ResolvedComponentPlan> plans) {
        Map<ComponentId, ResolvedComponentPlan> map = new LinkedHashMap<>();
        for (ResolvedComponentPlan plan : plans) {
            map.put(plan.component(), plan);
        }
        return map;
    }

    @Test
    @DisplayName("Commons_Run: every component from the commons-stored entries (Req 4.1)")
    void commonsRunResolvesEveryComponentFromEntries() {
        RunContext context = RunContext.commonsRun(COMMONS_ROOT, COMMONS);
        List<ResolvedComponentPlan> plans = new SourceResolver().resolve(set(), context, List.of());

        // No own language, no commons component: one plan per language x {library, server}.
        assertEquals(4, plans.size());
        Map<ComponentId, ResolvedComponentPlan> plan = byComponent(plans);
        assertTrue(plans.stream().allMatch(
            p -> p.reason() == ResolutionReason.CONFIGURATION_ENTRY),
            "every Commons_Run component derives from a Configuration_Entry");

        // Java library and server: clones at exactly (url, ref/branch) with the path.
        SourcePlan.Clone javaLib = assertInstanceOf(SourcePlan.Clone.class,
            plan.get(ComponentId.library("java")).plan());
        assertEquals("git@github.com:aws/aws-database-encryption-sdk-dynamodb.git", javaLib.url());
        assertEquals("main", javaLib.ref());
        assertEquals("esdk", javaLib.path());

        SourcePlan.Clone javaSrv = assertInstanceOf(SourcePlan.Clone.class,
            plan.get(ComponentId.server("java")).plan());
        assertEquals("git@github.com:aws/aws-database-encryption-sdk-dynamodb.git", javaSrv.url());
        assertEquals("main", javaSrv.ref());
        assertEquals("dbesdk/test-server/server", javaSrv.path());

        // Python server's Server_Location names the invoking repository (commons):
        // working tree, no clone.
        SourcePlan.WorkingTree pySrv = assertInstanceOf(SourcePlan.WorkingTree.class,
            plan.get(ComponentId.server("python")).plan());
        assertEquals(COMMONS_ROOT, pySrv.root());
        assertEquals("dbesdk/test-server/servers/python", pySrv.path());
    }

    @Test
    @DisplayName("Language_Repository_Run: own language always plans working-tree, ref ignored (Req 4.2)")
    void languageRunPlansWorkingTreeForOwnLanguage() {
        CommonsOrigin origin = new CommonsOrigin(
            "git@github.com:aws/aws-crypto-tools-commons.git", "feature-branch",
            ResolutionReason.CONFIGURATION_ENTRY);
        RunContext context = RunContext.languageRun(
            "java", JAVA_ROOT, COMMONS_ROOT, JAVA_REPO, origin);
        List<ResolvedComponentPlan> plans = new SourceResolver().resolve(set(), context, List.of());

        Map<ComponentId, ResolvedComponentPlan> plan = byComponent(plans);

        // The commons component: a clone at the origin coordinates.
        ResolvedComponentPlan commons = plan.get(ComponentId.commons());
        SourcePlan.Clone commonsClone = assertInstanceOf(SourcePlan.Clone.class, commons.plan());
        assertEquals("feature-branch", commonsClone.ref());
        assertEquals(ResolutionReason.CONFIGURATION_ENTRY, commons.reason());

        // Own language: library and server both working-tree at the repo root +
        // configured paths, reason working-tree, no clone.
        ResolvedComponentPlan ownLib = plan.get(ComponentId.library("java"));
        SourcePlan.WorkingTree libTree = assertInstanceOf(SourcePlan.WorkingTree.class, ownLib.plan());
        assertEquals(JAVA_ROOT, libTree.root());
        assertEquals("esdk", libTree.path());
        assertEquals(ResolutionReason.WORKING_TREE, ownLib.reason());

        ResolvedComponentPlan ownSrv = plan.get(ComponentId.server("java"));
        SourcePlan.WorkingTree srvTree = assertInstanceOf(SourcePlan.WorkingTree.class, ownSrv.plan());
        assertEquals(JAVA_ROOT, srvTree.root());
        assertEquals("dbesdk/test-server/server", srvTree.path());
        assertEquals(ResolutionReason.WORKING_TREE, ownSrv.reason());

        // Other language: from the commons-clone entries — python's library
        // clones; its server names commons, not the invoking Java repo, so it
        // clones too.
        assertEquals(ResolutionReason.CONFIGURATION_ENTRY,
            plan.get(ComponentId.library("python")).reason());
        SourcePlan.Clone pySrv = assertInstanceOf(SourcePlan.Clone.class,
            plan.get(ComponentId.server("python")).plan());
        assertEquals("main", pySrv.ref());
        assertEquals("dbesdk/test-server/servers/python", pySrv.path());
    }

    @Test
    @DisplayName("Configuration_Override fully replaces the stored entry (Req 4.6)")
    void overrideReplacesStoredEntrySolely() {
        CommonsOrigin origin = new CommonsOrigin(
            "git@github.com:aws/aws-crypto-tools-commons.git", "main",
            ResolutionReason.CONFIGURATION_ENTRY);
        RunContext context = RunContext.languageRun(
            "java", JAVA_ROOT, COMMONS_ROOT, JAVA_REPO, origin);

        ConfigurationEntry pythonOverride = new ConfigurationEntry("python", 4, 8092,
            new RepositoryCoordinates("aws-encryption-sdk-python",
                "https://github.com/fork/aws-encryption-sdk-python", "pinned-branch", "."),
            new ServerLocation(COMMONS,
                "git@github.com:aws/aws-crypto-tools-commons.git", "pinned-branch",
                "dbesdk/test-server/servers/python"),
            null, null);

        Map<ComponentId, ResolvedComponentPlan> plan = byComponent(
            new SourceResolver().resolve(set(), context, List.of(pythonOverride)));

        ResolvedComponentPlan lib = plan.get(ComponentId.library("python"));
        assertEquals(ResolutionReason.CONFIGURATION_OVERRIDE, lib.reason());
        SourcePlan.Clone libClone = assertInstanceOf(SourcePlan.Clone.class, lib.plan());
        assertEquals("https://github.com/fork/aws-encryption-sdk-python", libClone.url());
        assertEquals("pinned-branch", libClone.ref());

        ResolvedComponentPlan srv = plan.get(ComponentId.server("python"));
        assertEquals(ResolutionReason.CONFIGURATION_OVERRIDE, srv.reason());
        SourcePlan.Clone srvClone = assertInstanceOf(SourcePlan.Clone.class, srv.plan());
        assertEquals("pinned-branch", srvClone.ref());
    }

    @Test
    @DisplayName("commons branch selection: invocation override wins, else the entry branch (Req 4.5, 4.8)")
    void commonsBranchSelection() {
        RepositoryCoordinates entry = new RepositoryCoordinates(COMMONS,
            "git@github.com:aws/aws-crypto-tools-commons.git", "entry-branch", ".");

        CommonsOrigin fromEntry = CommonsOrigin.select(entry, null);
        assertEquals("entry-branch", fromEntry.branch());
        assertEquals(ResolutionReason.CONFIGURATION_ENTRY, fromEntry.reason());

        CommonsOrigin blankOverride = CommonsOrigin.select(entry, "  ");
        assertEquals("entry-branch", blankOverride.branch());
        assertEquals(ResolutionReason.CONFIGURATION_ENTRY, blankOverride.reason());

        CommonsOrigin overridden = CommonsOrigin.select(entry, "override-branch");
        assertEquals("override-branch", overridden.branch());
        assertEquals(ResolutionReason.INVOCATION_OVERRIDE, overridden.reason());
    }

    @Test
    @DisplayName("an overlay limited to one language leaves the repository's other languages cloned")
    void overlayAppliesOnlyToItsLanguages() {
        ConfigurationEntry rust = new ConfigurationEntry("rust", 1, 8093,
            new RepositoryCoordinates("aws-crypto-tools-rust",
                "git@github.com:aws/aws-crypto-tools-rust.git", "rust-branch", "esdk"),
            new ServerLocation("aws-crypto-tools-rust",
                "git@github.com:aws/aws-crypto-tools-rust.git", "rust-branch", "esdk-test-server"),
            null, null);
        ConfigurationEntry rustCpp = new ConfigurationEntry("rust-cpp", 1, 8094,
            new RepositoryCoordinates("aws-crypto-tools-rust",
                "git@github.com:aws/aws-crypto-tools-rust.git", "cpp-branch", "esdk"),
            new ServerLocation("aws-crypto-tools-rust-cpp",
                "git@github.com:aws/aws-crypto-tools-rust.git", "cpp-branch", "esdk-cpp-test-server"),
            null, null);
        CommonsConfiguration set = new CommonsConfiguration("esdk", List.of(), List.of(rust, rustCpp));
        Path checkout = Path.of("/work/rust-checkout");

        Map<ComponentId, ResolvedComponentPlan> plan = byComponent(new SourceResolver().resolve(
            set, RunContext.commonsRun(COMMONS_ROOT, COMMONS), List.of(),
            Map.of("aws-crypto-tools-rust", checkout), java.util.Set.of("rust")));

        SourcePlan.WorkingTree rustServer = assertInstanceOf(SourcePlan.WorkingTree.class,
            plan.get(ComponentId.server("rust")).plan());
        assertEquals(checkout, rustServer.root());
        SourcePlan.Clone cppServer = assertInstanceOf(SourcePlan.Clone.class,
            plan.get(ComponentId.server("rust-cpp")).plan());
        assertEquals("cpp-branch", cppServer.ref());
        assertInstanceOf(SourcePlan.Clone.class, plan.get(ComponentId.library("rust-cpp")).plan());
    }

    @Test
    @DisplayName("an overlay matches a server whose configured name is a label, by its URL")
    void overlayMatchesAServerLabelByUrl() {
        ConfigurationEntry rustCpp = new ConfigurationEntry("rust-cpp", 1, 8094,
            new RepositoryCoordinates("aws-crypto-tools-rust",
                "git@github.com:aws/aws-crypto-tools-rust.git", "cpp-branch", "esdk"),
            new ServerLocation("aws-crypto-tools-rust-cpp",
                "git@github.com:aws/aws-crypto-tools-rust.git", "cpp-branch", "esdk-cpp-test-server"),
            null, null);
        Path checkout = Path.of("/work/rust-checkout");

        Map<ComponentId, ResolvedComponentPlan> plan = byComponent(new SourceResolver().resolve(
            new CommonsConfiguration("esdk", List.of(), List.of(rustCpp)),
            RunContext.commonsRun(COMMONS_ROOT, COMMONS), List.of(),
            Map.of("aws-crypto-tools-rust", checkout), java.util.Set.of("rust-cpp")));

        assertEquals(checkout, assertInstanceOf(SourcePlan.WorkingTree.class,
            plan.get(ComponentId.server("rust-cpp")).plan()).root());
    }
}
