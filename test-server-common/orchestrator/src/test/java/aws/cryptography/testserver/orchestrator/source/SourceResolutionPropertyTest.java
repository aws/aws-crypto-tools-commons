package aws.cryptography.testserver.orchestrator.source;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import aws.cryptography.testserver.orchestrator.config.ConfigurationEntry;
import aws.cryptography.testserver.orchestrator.config.CommonsConfiguration;
import aws.cryptography.testserver.orchestrator.config.RepositoryCoordinates;
import aws.cryptography.testserver.orchestrator.config.ServerLocation;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import net.jqwik.api.Arbitraries;
import net.jqwik.api.Arbitrary;
import net.jqwik.api.ForAll;
import net.jqwik.api.GenerationMode;
import net.jqwik.api.Property;
import net.jqwik.api.Provide;
import net.jqwik.api.constraints.IntRange;

/**
 * Property-based test for the pure source-resolution planner
 * ({@link SourceResolver}), implementing the design's Property 3 over
 * generated commons configurations, Configuration_Overrides, and both run-context
 * kinds. Example-based coverage of the same rules lives in
 * {@link SourceResolverTest}.
 *
 * <p>Runs against the in-process planner only — no I/O, no git, nothing is
 * cloned (design "SourceResolver": planning is pure; execution is the
 * SourceMaterializer's job).
 */
class SourceResolutionPropertyTest {

    private static final List<String> LANG_POOL =
        List.of("java", "python", "javascript", "rust", "go", "dotnet");

    private static final List<String> CATALOG = List.of("streaming", "MPL");

    private static final Path COMMONS_ROOT = Path.of("/work/commons");
    private static final Path LANGUAGE_REPO_ROOT = Path.of("/work/language-repo");

    /** The three server-host shapes a generated Server_Location can take. */
    private enum ServerHost { INVOKING_REPOSITORY, OTHER_REPOSITORY_A, OTHER_REPOSITORY_B }

    private static ServerHost hostChoice(int hostSeed, int index) {
        return ServerHost.values()[Math.floorMod(hostSeed + index, ServerHost.values().length)];
    }

    /**
     * A structurally complete entry for {@code language} whose Server_Location
     * repository is decided by {@code host} relative to the run's invoking
     * repository, with all coordinates salted so the assertions verify exact
     * echoing rather than coincidence.
     */
    private static ConfigurationEntry entry(
            String language, int port, ServerHost host, String invokingRepository,
            int salt, String tag) {
        String serverRepo = switch (host) {
            case INVOKING_REPOSITORY -> invokingRepository;
            case OTHER_REPOSITORY_A -> "other-repo-a-" + language;
            case OTHER_REPOSITORY_B -> "other-repo-b-" + language;
        };
        return new ConfigurationEntry(language, 3, port,
            new RepositoryCoordinates(
                tag + "lib-repo-" + language,
                "git@github.com:aws/" + tag + "lib-" + language + "-" + salt + ".git",
                tag + "lib-branch-" + language + "-" + salt,
                tag + "lib-path/" + language),
            new ServerLocation(
                serverRepo,
                "git@github.com:aws/" + tag + "srv-" + language + "-" + salt + ".git",
                tag + "srv-ref-" + language + "-" + salt,
                tag + "srv-path/" + language),
            null, null);
    }

    private static Map<ComponentId, ResolvedComponentPlan> byComponent(
            List<ResolvedComponentPlan> plans) {
        Map<ComponentId, ResolvedComponentPlan> map = new LinkedHashMap<>();
        for (ResolvedComponentPlan plan : plans) {
            ResolvedComponentPlan previous = map.put(plan.component(), plan);
            assertTrue(previous == null,
                "the plan must contain exactly one entry per component, but "
                + plan.component() + " appeared twice");
        }
        return map;
    }

    // Feature: test-server-factoring, Property 3: Source resolution is a pure function of the effective configuration and context
    //
    // The resolution plan derives each language's server component solely from
    // the run-effective Server_Location and each library component solely from
    // the run-effective library coordinates. In a Language_Repository_Run the
    // own language resolves to the working tree (its ref ignored, no clone),
    // while other languages derive from the commons-clone entries except those
    // replaced by an override. A Server_Location naming a repository other than
    // the invoking one yields a clone plan at exactly (url, ref) with the
    // location's path; naming the invoking repository yields a working-tree
    // plan with the location's path.
    @Property(tries = 300, generation = GenerationMode.RANDOMIZED)
    void sourceResolutionIsAPureFunctionOfTheEffectiveConfigurationAndContext(
            @ForAll("languageSubsetsMin2") List<String> langs,
            @ForAll boolean languageRun,
            @ForAll @IntRange(min = 0, max = 5) int ownSeed,
            @ForAll @IntRange(min = 0, max = 5) int storedHostSeed,
            @ForAll @IntRange(min = 0, max = 5) int overrideHostSeed,
            @ForAll @IntRange(min = 0, max = 3) int overrideSelectionSeed,
            @ForAll boolean overridesRequested,
            @ForAll boolean commonsBranchOverridden,
            @ForAll @IntRange(min = 0, max = 99) int salt) {

        // --- Arrange: run context ------------------------------------------
        String ownLanguage = languageRun ? langs.get(Math.floorMod(ownSeed, langs.size())) : null;
        String invokingRepository = languageRun
            ? "language-repo-" + ownLanguage
            : "aws-crypto-tools-commons";

        CommonsOrigin origin = languageRun
            ? new CommonsOrigin(
                "git@github.com:aws/aws-crypto-tools-commons-" + salt + ".git",
                "commons-branch-" + salt,
                commonsBranchOverridden
                    ? ResolutionReason.INVOCATION_OVERRIDE
                    : ResolutionReason.CONFIGURATION_ENTRY)
            : null;
        RunContext context = languageRun
            ? RunContext.languageRun(ownLanguage, LANGUAGE_REPO_ROOT, COMMONS_ROOT,
                invokingRepository, origin)
            : RunContext.commonsRun(COMMONS_ROOT, invokingRepository);

        // --- Arrange: commons-stored entries with varied Server_Location
        // repositories (some naming the invoking repository, some others) ----
        List<ConfigurationEntry> entries = new ArrayList<>();
        int port = 1024;
        for (int i = 0; i < langs.size(); i++) {
            entries.add(entry(langs.get(i), port++,
                hostChoice(storedHostSeed, i), invokingRepository, salt, ""));
        }
        CommonsConfiguration set = new CommonsConfiguration("esdk", CATALOG, entries);

        // --- Arrange: full-replacement overrides for a subset of the
        // non-own languages (overrides only exist in Language_Repository_Runs;
        // the own language never has one — validation rejects it) ------------
        Map<String, ConfigurationEntry> overrideByLanguage = new LinkedHashMap<>();
        if (languageRun && overridesRequested) {
            int overridePort = 9001;
            for (int i = 0; i < langs.size(); i++) {
                String language = langs.get(i);
                if (language.equals(ownLanguage)
                        || Math.floorMod(overrideSelectionSeed + i, 2) != 0) {
                    continue;
                }
                overrideByLanguage.put(language, entry(language, overridePort++,
                    hostChoice(overrideHostSeed, i), invokingRepository, salt, "ovr-"));
            }
        }
        List<ConfigurationEntry> overrides = List.copyOf(overrideByLanguage.values());

        // --- Act ------------------------------------------------------------
        List<ResolvedComponentPlan> plans =
            new SourceResolver().resolve(set, context, overrides);
        Map<ComponentId, ResolvedComponentPlan> plan = byComponent(plans);

        // --- Assert: component population — one (library, server) pair per
        // language, plus the commons component iff a Language_Repository_Run --
        assertEquals(2 * langs.size() + (languageRun ? 1 : 0), plans.size(),
            "the plan must cover every language x {library, server}"
            + (languageRun ? " plus the commons component" : ""));

        if (languageRun) {
            ResolvedComponentPlan commons = plan.get(ComponentId.commons());
            assertNotNull(commons, "a Language_Repository_Run plans the commons clone");
            SourcePlan.Clone commonsClone =
                assertInstanceOf(SourcePlan.Clone.class, commons.plan(),
                    "the commons component of a Language_Repository_Run is a clone plan");
            assertEquals(origin.url(), commonsClone.url());
            assertEquals(origin.branch(), commonsClone.ref());
            assertEquals(origin.reason(), commons.reason(),
                "the commons component carries the branch-selection reason");
        } else {
            assertFalse(plan.containsKey(ComponentId.commons()),
                "a Commons_Run plans no commons component (the working tree is implicit)");
        }

        // --- Assert: every language's pair matches the design rules exactly --
        for (String language : langs) {
            ConfigurationEntry stored = set.forLanguage(language);
            ConfigurationEntry override = overrideByLanguage.get(language);
            ConfigurationEntry effective = override != null ? override : stored;
            boolean own = languageRun && language.equals(ownLanguage);

            ResolvedComponentPlan library = plan.get(ComponentId.library(language));
            ResolvedComponentPlan server = plan.get(ComponentId.server(language));
            assertNotNull(library, "missing library plan for " + language);
            assertNotNull(server, "missing server plan for " + language);

            if (own) {
                // Own language: library and server both resolve to the working
                // tree — the Server_Location ref is ignored and no clone is
                // planned; reason working-tree.
                assertEquals(ResolutionReason.WORKING_TREE, library.reason(),
                    "own-language library reason");
                assertEquals(ResolutionReason.WORKING_TREE, server.reason(),
                    "own-language server reason");

                SourcePlan.WorkingTree libTree = assertInstanceOf(
                    SourcePlan.WorkingTree.class, library.plan(),
                    "own-language library must be a working-tree plan (no clone)");
                assertEquals(LANGUAGE_REPO_ROOT, libTree.root());
                assertEquals(effective.libraryRepository().path(), libTree.path());

                SourcePlan.WorkingTree srvTree = assertInstanceOf(
                    SourcePlan.WorkingTree.class, server.plan(),
                    "own-language server must be a working-tree plan (ref ignored, no clone)");
                assertEquals(LANGUAGE_REPO_ROOT, srvTree.root());
                assertEquals(effective.serverLocation().path(), srvTree.path());
                continue;
            }

            // Other (or Commons_Run) language: the reason states which entry the
            // component derives from — the override's when overridden, the
            // commons-stored / commons-clone entry's otherwise.
            ResolutionReason expectedReason = override != null
                ? ResolutionReason.CONFIGURATION_OVERRIDE
                : ResolutionReason.CONFIGURATION_ENTRY;
            assertEquals(expectedReason, library.reason(), language + " library reason");
            assertEquals(expectedReason, server.reason(), language + " server reason");

            // Library: solely the run-effective library repository coordinates.
            RepositoryCoordinates lib = effective.libraryRepository();
            SourcePlan.Clone libClone = assertInstanceOf(
                SourcePlan.Clone.class, library.plan(),
                language + " library must be a clone of the effective library repository");
            assertEquals(lib.url(), libClone.url(), language + " library clone url");
            assertEquals(lib.branch(), libClone.ref(), language + " library clone ref");
            assertEquals(lib.path(), libClone.path(), language + " library clone path");

            // Server: solely the run-effective Server_Location.
            ServerLocation location = effective.serverLocation();
            if (location.repository().equals(invokingRepository)) {
                // Naming the invoking repository always yields a working-tree
                // plan with the location's path.
                SourcePlan.WorkingTree tree = assertInstanceOf(
                    SourcePlan.WorkingTree.class, server.plan(),
                    language + " server naming the invoking repository must be a working-tree plan");
                assertEquals(context.invokingWorkingTreeRoot(), tree.root(),
                    language + " server working-tree root");
                assertEquals(location.path(), tree.path(), language + " server working-tree path");
            } else {
                // Naming any other repository always yields a clone plan at
                // exactly (url, ref) with the location's path.
                SourcePlan.Clone clone = assertInstanceOf(
                    SourcePlan.Clone.class, server.plan(),
                    language + " server naming another repository must be a clone plan");
                assertEquals(location.url(), clone.url(), language + " server clone url");
                assertEquals(location.ref(), clone.ref(), language + " server clone ref");
                assertEquals(location.path(), clone.path(), language + " server clone path");
            }
        }
    }

    @Provide
    Arbitrary<List<String>> languageSubsetsMin2() {
        return Arbitraries.subsetOf(LANG_POOL).ofMinSize(2).map(List::copyOf);
    }
}
