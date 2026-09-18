package aws.cryptography.esdk.testserver.orchestrator.source;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;

import aws.cryptography.esdk.testserver.orchestrator.config.ConfigurationEntry;
import aws.cryptography.esdk.testserver.orchestrator.config.ConfigurationSet;
import aws.cryptography.esdk.testserver.orchestrator.config.RepositoryCoordinates;
import aws.cryptography.esdk.testserver.orchestrator.config.ServerLocation;
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
    private static final String JAVA_REPO = "aws-crypto-tools-java";
    private static final Path COMMONS_ROOT = Path.of("/work/commons");
    private static final Path JAVA_ROOT = Path.of("/work/java-repo");

    private static ConfigurationEntry javaEntry() {
        return new ConfigurationEntry("java", 3, 8091,
            new RepositoryCoordinates(JAVA_REPO,
                "git@github.com:aws/aws-crypto-tools-java.git", "main", "esdk"),
            new ServerLocation(JAVA_REPO,
                "git@github.com:aws/aws-crypto-tools-java.git", "main",
                "esdk/test-server/server"),
            null, null);
    }

    private static ConfigurationEntry pythonEntry() {
        return new ConfigurationEntry("python", 4, 8092,
            new RepositoryCoordinates("aws-encryption-sdk-python",
                "https://github.com/aws/aws-encryption-sdk-python", "master", "."),
            new ServerLocation(COMMONS,
                "git@github.com:aws/aws-crypto-tools-commons.git", "main",
                "esdk/test-server/servers/python"),
            List.of("streaming", "MPL"), List.of());
    }

    private static ConfigurationSet set() {
        return new ConfigurationSet("esdk", List.of("streaming", "MPL"),
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
        assertEquals("git@github.com:aws/aws-crypto-tools-java.git", javaLib.url());
        assertEquals("main", javaLib.ref());
        assertEquals("esdk", javaLib.path());

        SourcePlan.Clone javaSrv = assertInstanceOf(SourcePlan.Clone.class,
            plan.get(ComponentId.server("java")).plan());
        assertEquals("git@github.com:aws/aws-crypto-tools-java.git", javaSrv.url());
        assertEquals("main", javaSrv.ref());
        assertEquals("esdk/test-server/server", javaSrv.path());

        // Python server's Server_Location names the invoking repository (commons):
        // working tree, no clone.
        SourcePlan.WorkingTree pySrv = assertInstanceOf(SourcePlan.WorkingTree.class,
            plan.get(ComponentId.server("python")).plan());
        assertEquals(COMMONS_ROOT, pySrv.root());
        assertEquals("esdk/test-server/servers/python", pySrv.path());
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
        assertEquals("esdk/test-server/server", srvTree.path());
        assertEquals(ResolutionReason.WORKING_TREE, ownSrv.reason());

        // Other language: from the commons-clone entries — python's library
        // clones; its server names commons, not the invoking Java repo, so it
        // clones too.
        assertEquals(ResolutionReason.CONFIGURATION_ENTRY,
            plan.get(ComponentId.library("python")).reason());
        SourcePlan.Clone pySrv = assertInstanceOf(SourcePlan.Clone.class,
            plan.get(ComponentId.server("python")).plan());
        assertEquals("main", pySrv.ref());
        assertEquals("esdk/test-server/servers/python", pySrv.path());
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
                "esdk/test-server/servers/python"),
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
    @DisplayName("local override: a non-own language is planned from its local working tree (dev overlay)")
    void localOverridePlansWorkingTreeForAnotherLanguage() {
        RunContext context = RunContext.commonsRun(COMMONS_ROOT, COMMONS);
        Path javaLocal = Path.of("/work/local-java");
        Map<ComponentId, ResolvedComponentPlan> plan = byComponent(new SourceResolver()
            .resolve(set(), context, List.of(), Map.of("java", javaLocal)));

        ResolvedComponentPlan lib = plan.get(ComponentId.library("java"));
        assertEquals(ResolutionReason.LOCAL_OVERRIDE, lib.reason());
        SourcePlan.WorkingTree libTree = assertInstanceOf(SourcePlan.WorkingTree.class, lib.plan());
        assertEquals(javaLocal, libTree.root());
        assertEquals("esdk", libTree.path());

        ResolvedComponentPlan srv = plan.get(ComponentId.server("java"));
        assertEquals(ResolutionReason.LOCAL_OVERRIDE, srv.reason());
        SourcePlan.WorkingTree srvTree = assertInstanceOf(SourcePlan.WorkingTree.class, srv.plan());
        assertEquals(javaLocal, srvTree.root());
        assertEquals("esdk/test-server/server", srvTree.path());

        // A language absent from the overlay is unaffected: python still clones its library.
        assertInstanceOf(SourcePlan.Clone.class, plan.get(ComponentId.library("python")).plan());
    }

    @Test
    @DisplayName("local override never applies to the own language (already a working tree)")
    void localOverrideIgnoredForOwnLanguage() {
        CommonsOrigin origin = new CommonsOrigin(
            "git@github.com:aws/aws-crypto-tools-commons.git", "main",
            ResolutionReason.CONFIGURATION_ENTRY);
        RunContext context = RunContext.languageRun(
            "java", JAVA_ROOT, COMMONS_ROOT, JAVA_REPO, origin);

        Map<ComponentId, ResolvedComponentPlan> plan = byComponent(new SourceResolver()
            .resolve(set(), context, List.of(), Map.of("java", Path.of("/work/elsewhere"))));

        ResolvedComponentPlan srv = plan.get(ComponentId.server("java"));
        assertEquals(ResolutionReason.WORKING_TREE, srv.reason());
        SourcePlan.WorkingTree tree = assertInstanceOf(SourcePlan.WorkingTree.class, srv.plan());
        assertEquals(JAVA_ROOT, tree.root(),
            "own language uses languageRepoRoot, not the overlay path");
    }

    @Test
    @DisplayName("local override wins over a Configuration_Override (dev intent beats a pinned clone)")
    void localOverrideWinsOverConfigurationOverride() {
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
                "esdk/test-server/servers/python"),
            null, null);
        Path pyLocal = Path.of("/work/local-python");

        Map<ComponentId, ResolvedComponentPlan> plan = byComponent(new SourceResolver()
            .resolve(set(), context, List.of(pythonOverride), Map.of("python", pyLocal)));

        ResolvedComponentPlan srv = plan.get(ComponentId.server("python"));
        assertEquals(ResolutionReason.LOCAL_OVERRIDE, srv.reason());
        SourcePlan.WorkingTree tree = assertInstanceOf(SourcePlan.WorkingTree.class, srv.plan());
        assertEquals(pyLocal, tree.root());
    }
}
