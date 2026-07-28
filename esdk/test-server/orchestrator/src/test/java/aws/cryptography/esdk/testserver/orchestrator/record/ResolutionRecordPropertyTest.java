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
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import net.jqwik.api.Arbitraries;
import net.jqwik.api.Arbitrary;
import net.jqwik.api.ForAll;
import net.jqwik.api.GenerationMode;
import net.jqwik.api.Property;
import net.jqwik.api.Provide;
import net.jqwik.api.constraints.IntRange;

/**
 * Property-based test for the Resolution_Record (task 4.2), implementing the
 * design's Property 5 over generated resolution outcomes — successes and
 * failures, clone and working-tree plans, both run-context kinds. Example-based
 * coverage of the same behavior lives in {@link ResolutionRecordTest}.
 *
 * <p>Runs against in-memory {@link MaterializedSources} only — no I/O, no git,
 * nothing is cloned.
 */
class ResolutionRecordPropertyTest {

    private static final List<String> LANG_POOL =
        List.of("java", "python", "rust", "go", "dotnet");

    private static final Path COMMONS_ROOT = Path.of("/work/commons");
    private static final Path LANGUAGE_REPO_ROOT = Path.of("/work/language-repo");

    // ------------------------------------------------------------------
    // Deterministic coordinate generation, shared between the outcome
    // builders and the faithfulness assertions so the test verifies exact
    // echoing rather than coincidence.
    // ------------------------------------------------------------------

    private static String cloneRepositoryName(ComponentId component, int salt) {
        String stem = switch (component.kind()) {
            case LIBRARY -> "lib-repo-" + component.language();
            case SERVER -> "srv-repo-" + component.language();
            case COMMONS -> "aws-crypto-tools-commons";
        };
        return stem + "-" + salt;
    }

    private static String cloneUrl(ComponentId component, int salt) {
        return "git@github.com:aws/" + cloneRepositoryName(component, salt) + ".git";
    }

    private static String cloneRef(ComponentId component, int salt) {
        return "ref-" + component.toString().replace(':', '-') + "-" + salt;
    }

    private static String planPath(ComponentId component) {
        return switch (component.kind()) {
            case LIBRARY -> "lib-path/" + component.language();
            case SERVER -> "srv-path/" + component.language();
            case COMMONS -> ".";
        };
    }

    private static String commitOf(ComponentId component, int salt) {
        return "commit-" + component.toString().replace(':', '-') + "-" + salt;
    }

    private static String causeOf(ComponentId component, int salt) {
        return "could not materialize " + component + " (salt " + salt + ")";
    }

    private static boolean bit(int mask, int index) {
        return (mask >> index & 1) == 1;
    }

    // Feature: test-server-factoring, Property 5: The Resolution_Record is complete and faithful
    //
    // For any generated resolution outcome (successful and failed components,
    // any run context): the produced Resolution_Record contains exactly one
    // component for every language's library, one for every language's
    // Language_Server, and — in a Language_Repository_Run — one for the commons
    // clone; every successful component carries the repository, reference,
    // resolved commit, and a reason drawn from {configuration-entry,
    // configuration-override, working-tree, invocation-override} matching its
    // plan; every working-tree component carries the working tree's checked-out
    // commit and its uncommitted-modifications flag; every failed component
    // carries its attempted coordinates (repository, reference, and path for
    // server components) and the failure cause.
    //
    // Validates: Requirements 5.1, 5.2, 5.4, 5.7
    @Property(tries = 300, generation = GenerationMode.RANDOMIZED)
    void theResolutionRecordIsCompleteAndFaithful(
            @ForAll("languageSubsets") List<String> langs,
            @ForAll boolean languageRun,
            @ForAll @IntRange(min = 0, max = 4) int ownSeed,
            @ForAll @IntRange(min = 0, max = 4095) int failureMask,
            @ForAll @IntRange(min = 0, max = 4095) int dirtyMask,
            @ForAll @IntRange(min = 0, max = 4095) int overrideMask,
            @ForAll @IntRange(min = 0, max = 4095) int hostMask,
            @ForAll boolean commonsInvocationOverride,
            @ForAll @IntRange(min = 0, max = 99) int salt,
            @ForAll @IntRange(min = 0, max = 4095) int dropSeed) {

        // --- Arrange: run context ------------------------------------------
        String ownLanguage = languageRun ? langs.get(Math.floorMod(ownSeed, langs.size())) : null;
        String invokingRepository = languageRun
            ? "language-repo-" + ownLanguage
            : "aws-crypto-tools-commons";
        ComponentId commonsId = ComponentId.commons();
        RunContext context = languageRun
            ? RunContext.languageRun(ownLanguage, LANGUAGE_REPO_ROOT, COMMONS_ROOT,
                invokingRepository,
                new CommonsOrigin(cloneUrl(commonsId, salt), cloneRef(commonsId, salt),
                    commonsInvocationOverride
                        ? ResolutionReason.INVOCATION_OVERRIDE
                        : ResolutionReason.CONFIGURATION_ENTRY))
            : RunContext.commonsRun(COMMONS_ROOT, invokingRepository);

        // --- Arrange: one outcome per expected component, reasons and plan
        // shapes consistent with the context ---------------------------------
        List<MaterializedSources.Outcome> outcomes = new ArrayList<>();
        int index = 0;
        for (String language : langs) {
            boolean own = languageRun && language.equals(ownLanguage);
            for (ComponentId component
                    : List.of(ComponentId.library(language), ComponentId.server(language))) {
                // The own language of a Language_Repository_Run always resolves
                // to the working tree; a Commons_Run server whose
                // Server_Location names the invoking repository does too. Every
                // other component is a clone at generated coordinates, chosen
                // by a Configuration_Entry or — in a Language_Repository_Run —
                // a Configuration_Override.
                boolean workingTree = own
                    || (!languageRun
                        && component.kind() == ComponentId.Kind.SERVER
                        && bit(hostMask, index));
                SourcePlan plan;
                ResolutionReason reason;
                if (workingTree) {
                    plan = new SourcePlan.WorkingTree(
                        context.invokingWorkingTreeRoot(), planPath(component));
                    reason = ResolutionReason.WORKING_TREE;
                } else {
                    plan = new SourcePlan.Clone(
                        cloneUrl(component, salt), cloneRef(component, salt),
                        planPath(component));
                    reason = languageRun && bit(overrideMask, index)
                        ? ResolutionReason.CONFIGURATION_OVERRIDE
                        : ResolutionReason.CONFIGURATION_ENTRY;
                }
                outcomes.add(bit(failureMask, index)
                    ? new MaterializedSources.Failure(component, plan, reason,
                        causeOf(component, salt))
                    : new MaterializedSources.Success(component, plan, reason,
                        Path.of("/scratch", component.toString().replace(':', '-')),
                        commitOf(component, salt),
                        workingTree ? "wt-branch-" + salt : cloneRef(component, salt),
                        workingTree ? bit(dirtyMask, index) : null));
                index++;
            }
        }
        if (languageRun) {
            SourcePlan.Clone plan = new SourcePlan.Clone(
                cloneUrl(commonsId, salt), cloneRef(commonsId, salt), planPath(commonsId));
            ResolutionReason reason = commonsInvocationOverride
                ? ResolutionReason.INVOCATION_OVERRIDE
                : ResolutionReason.CONFIGURATION_ENTRY;
            outcomes.add(bit(failureMask, index)
                ? new MaterializedSources.Failure(commonsId, plan, reason,
                    causeOf(commonsId, salt))
                : new MaterializedSources.Success(commonsId, plan, reason,
                    Path.of("/scratch/commons"), commitOf(commonsId, salt),
                    cloneRef(commonsId, salt), null));
        }
        MaterializedSources sources = new MaterializedSources(outcomes);

        // --- Act ------------------------------------------------------------
        ResolutionRecord record = ResolutionRecord.assemble(context, sources);

        // --- Assert: exactly one record entry per expected component — every
        // language's library and server, plus commons iff a
        // Language_Repository_Run — and the full outcome set is complete ------
        assertEquals(languageRun ? "language:" + ownLanguage : "commons", record.runContext());

        Map<String, ResolutionRecord.Component> componentsById = new LinkedHashMap<>();
        for (ResolutionRecord.Component component : record.components()) {
            assertNull(componentsById.put(component.component(), component),
                "duplicate record component: " + component.component());
        }
        Map<String, ResolutionRecord.Failure> failuresById = new LinkedHashMap<>();
        for (ResolutionRecord.Failure failure : record.failures()) {
            assertNull(failuresById.put(failure.component(), failure),
                "duplicate record failure: " + failure.component());
        }
        assertEquals(2 * langs.size() + (languageRun ? 1 : 0),
            componentsById.size() + failuresById.size(),
            "one record entry per language x {library, server}"
            + (languageRun ? " plus the commons clone" : ""));
        for (MaterializedSources.Outcome outcome : outcomes) {
            String id = outcome.component().toString();
            assertTrue(componentsById.containsKey(id) ^ failuresById.containsKey(id),
                id + " must appear exactly once, as a component or a failure");
        }

        ResolutionRecord.Completeness completeness = record.completeness(Set.copyOf(langs));
        assertTrue(completeness.complete(),
            "a record over the full outcome set is complete, but: "
            + completeness.problems());

        // --- Assert: field faithfulness per outcome --------------------------
        for (MaterializedSources.Outcome outcome : outcomes) {
            ComponentId componentId = outcome.component();
            String id = componentId.toString();
            boolean server = componentId.kind() == ComponentId.Kind.SERVER;
            boolean workingTree = outcome.plan() instanceof SourcePlan.WorkingTree;
            String expectedRepository = workingTree
                ? invokingRepository
                : cloneRepositoryName(componentId, salt);

            switch (outcome) {
                case MaterializedSources.Success success -> {
                    ResolutionRecord.Component component = componentsById.get(id);
                    assertEquals(expectedRepository, component.repository(),
                        id + " repository");
                    assertEquals(success.reference(), component.reference(), id + " reference");
                    assertEquals(success.commit(), component.commit(),
                        id + " resolved commit (the working tree's checked-out commit"
                        + " for working-tree components)");
                    assertEquals(success.reason(), component.reason(), id + " reason");
                    String label = component.reason().label();
                    if (workingTree) {
                        assertEquals("working-tree", label,
                            id + ": working-tree components carry the working-tree reason");
                        assertEquals(success.dirty(), component.dirty(),
                            id + " uncommitted-modifications flag (Requirement 5.7)");
                    } else {
                        assertTrue(Set.of("configuration-entry", "configuration-override",
                                "invocation-override").contains(label),
                            id + " clone reason label must be a clone reason, was " + label);
                        assertNull(component.dirty(), id + ": clones carry no dirty flag");
                    }
                    if (server) {
                        assertEquals(planPath(componentId), component.path(),
                            id + " server path");
                    } else {
                        assertNull(component.path(),
                            id + ": path is recorded for server components only");
                    }
                }
                case MaterializedSources.Failure failure -> {
                    ResolutionRecord.Failure recorded = failuresById.get(id);
                    assertEquals(expectedRepository, recorded.repository(),
                        id + " attempted repository");
                    if (workingTree) {
                        assertNull(recorded.reference(),
                            id + ": no reference was requested for a working tree");
                    } else {
                        assertEquals(cloneRef(componentId, salt), recorded.reference(),
                            id + " attempted reference");
                    }
                    if (server) {
                        assertEquals(planPath(componentId), recorded.path(),
                            id + " attempted path");
                    } else {
                        assertNull(recorded.path(),
                            id + ": path is recorded for server components only");
                    }
                    assertEquals(failure.cause(), recorded.cause(), id + " failure cause");
                }
            }
        }

        // --- Assert: dropping any one outcome makes the record incomplete ----
        int dropIndex = Math.floorMod(dropSeed, outcomes.size());
        String droppedId = outcomes.get(dropIndex).component().toString();
        List<MaterializedSources.Outcome> reduced = new ArrayList<>(outcomes);
        reduced.remove(dropIndex);
        ResolutionRecord incomplete =
            ResolutionRecord.assemble(context, new MaterializedSources(reduced));

        ResolutionRecord.Completeness gate = incomplete.completeness(Set.copyOf(langs));

        assertFalse(gate.complete(),
            "dropping " + droppedId + " must fail the completeness gate");
        assertTrue(gate.problems().contains("missing component: " + droppedId),
            "the completeness problems must name the missing component " + droppedId
            + ", but were: " + gate.problems());
    }

    @Provide
    Arbitrary<List<String>> languageSubsets() {
        return Arbitraries.subsetOf(LANG_POOL).ofMinSize(1).map(List::copyOf);
    }
}
