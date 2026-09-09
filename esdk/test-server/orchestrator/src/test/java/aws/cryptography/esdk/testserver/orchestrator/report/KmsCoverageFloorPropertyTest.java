package aws.cryptography.esdk.testserver.orchestrator.report;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import net.jqwik.api.Arbitraries;
import net.jqwik.api.Arbitrary;
import net.jqwik.api.Combinators;
import net.jqwik.api.ForAll;
import net.jqwik.api.GenerationMode;
import net.jqwik.api.Property;
import net.jqwik.api.Provide;
import org.junit.jupiter.api.Test;

/**
 * Property-based test for the {@link ResultReporter} KMS coverage floor
 * (design Property 10): for any generated launched-target set and multiset of
 * parsed executions, the run reports success only if, for every
 * (encrypt, decrypt) pair over the launched targets and every required KMS
 * scenario, at least one passed execution exists whose name matches that
 * scenario and pair; any missing combination fails the run naming the scenario
 * and the pair.
 *
 * <p>Each generated case starts from full coverage (one passed execution per
 * pair × required scenario, in the Tests' stable
 * {@code …[<scenario>…] <encrypt>-><decrypt>} naming) and punches a random set
 * of (scenario, pair) holes. Cases may replace each removed execution with a
 * <em>decoy</em> whose scenario label merely extends the removed one — coverage
 * provided only by a longer label must never satisfy a shorter scenario
 * (label-boundary matching, e.g. {@code awsKms} vs {@code [awsKmsMrk]}).
 */
class KmsCoverageFloorPropertyTest {

    private final ResultReporter reporter = new ResultReporter();

    // Feature: test-server-factoring, Property 10: The KMS coverage floor gates success
    @Property(tries = 300, generation = GenerationMode.RANDOMIZED)
    void kmsCoverageFloorGatesSuccess(@ForAll("cases") Case c) {
        List<TestExecution> executions = new ArrayList<>();

        // Full KMS coverage over the launched pairwise product, minus the holes.
        for (String encrypt : c.targets()) {
            for (String decrypt : c.targets()) {
                for (String scenario : ResultReporter.REQUIRED_KMS_SCENARIOS) {
                    Hole combination = new Hole(scenario, encrypt, decrypt);
                    if (!c.holes().contains(combination)) {
                        executions.add(TestExecution.passed(
                            "Tests#blob[" + scenario + "] " + encrypt + "->" + decrypt));
                    } else if (c.decoys()) {
                        // A passed execution whose scenario label extends the
                        // removed one; it must not fill the hole.
                        executions.add(TestExecution.passed(
                            "Tests#blob[" + scenario + "Xtra] " + encrypt + "->" + decrypt));
                    }
                }
            }
        }

        // Non-KMS noise (passed and skipped) never affects the floor.
        String noisePair = c.targets().get(0) + "->" + c.targets().get(0);
        for (int i = 0; i < c.noise(); i++) {
            executions.add(TestExecution.passed(
                "Tests#blob[rawAes+default." + i + "] " + noisePair));
            executions.add(TestExecution.skipped(
                "Tests#stream[rawAes+default." + i + "] " + noisePair,
                "feature-gated skip"));
        }

        Result result = reporter.report(executions, c.targets(), List.of());

        if (c.holes().isEmpty()) {
            assertTrue(result.succeeded(),
                () -> "full KMS coverage over " + c.targets() + " must pass: " + result);
        } else {
            assertFalse(result.succeeded(),
                () -> "holes " + c.holes() + " must fail the run: " + result);
            for (Hole hole : c.holes()) {
                String pair = hole.encrypt() + "->" + hole.decrypt();
                assertTrue(result.details().stream().anyMatch(
                        d -> d.contains("scenario " + hole.scenario() + " ")
                            && d.contains(pair)),
                    () -> "each hole must be named with its scenario and pair ("
                        + hole.scenario() + ", " + pair + "): " + result.details());
            }
        }
    }

    // A language that declares the KMS Feature unsupported skips the KMS
    // scenarios visibly; those recorded skips exempt its combinations from the
    // floor — an explicit exemption, not silent coverage loss (Requirement 10.4).
    @Test
    void featureGatedSkipsExemptCombinationsFromTheFloor() {
        List<String> targets = List.of("java-v3", "rust-v1");
        List<TestExecution> executions = new ArrayList<>();
        for (String encrypt : targets) {
            for (String decrypt : targets) {
                for (String scenario : ResultReporter.REQUIRED_KMS_SCENARIOS) {
                    String name = "Tests#blob[" + scenario + "] " + encrypt + "->" + decrypt;
                    // A combination involving the KMS-incapable target skips; the
                    // fully KMS-capable pair passes.
                    if (encrypt.equals("rust-v1") || decrypt.equals("rust-v1")) {
                        executions.add(TestExecution.skipped(
                            name, "feature-gated skip: feature=MPL unsupported by [rust]"));
                    } else {
                        executions.add(TestExecution.passed(name));
                    }
                }
            }
        }
        Result result = reporter.report(executions, targets, List.of());
        assertTrue(result.succeeded(),
            () -> "feature-gated KMS skips must exempt their combinations: " + result);
    }

    @Provide
    Arbitrary<Case> cases() {
        Arbitrary<List<String>> targets = Arbitraries
            .of("java-v3", "python-v4", "rust-v1")
            .set().ofMinSize(1).ofMaxSize(3)
            .map(s -> List.copyOf(new ArrayList<>(s)));
        return targets.flatMap(t -> {
            List<Hole> combinations = new ArrayList<>();
            for (String encrypt : t) {
                for (String decrypt : t) {
                    for (String scenario : ResultReporter.REQUIRED_KMS_SCENARIOS) {
                        combinations.add(new Hole(scenario, encrypt, decrypt));
                    }
                }
            }
            return Combinators.combine(
                    Arbitraries.subsetOf(combinations),
                    Arbitraries.of(true, false),
                    Arbitraries.integers().between(0, 3))
                .as((holes, decoys, noise) -> new Case(t, holes, decoys, noise));
        });
    }

    /** One required (scenario, encrypt, decrypt) coverage combination. */
    private record Hole(String scenario, String encrypt, String decrypt) { }

    /** A generated launched-target set with coverage holes and noise. */
    private record Case(List<String> targets, Set<Hole> holes, boolean decoys, int noise) { }
}
