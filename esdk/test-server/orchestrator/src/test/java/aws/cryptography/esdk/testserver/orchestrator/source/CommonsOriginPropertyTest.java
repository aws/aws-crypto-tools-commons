package aws.cryptography.esdk.testserver.orchestrator.source;

import static org.junit.jupiter.api.Assertions.assertEquals;

import aws.cryptography.esdk.testserver.orchestrator.config.RepositoryCoordinates;
import net.jqwik.api.Arbitraries;
import net.jqwik.api.Arbitrary;
import net.jqwik.api.Combinators;
import net.jqwik.api.ForAll;
import net.jqwik.api.Property;
import net.jqwik.api.Provide;

/**
 * Property-based test for commons-branch selection (design Property 4): for
 * any generated Commons_Configuration_Entry branch and optional
 * invocation-time branch override, {@link CommonsOrigin#select} picks the
 * override when a non-blank one is supplied (reason {@code invocation-override})
 * and the entry's branch otherwise (reason {@code configuration-entry}). The
 * clone URL always passes through from the entry unchanged.
 *
 * <p>Everything under test is pure — no I/O, no git, no servers.
 */
class CommonsOriginPropertyTest {

    /**
     * One generated case: the Commons_Configuration_Entry coordinates and the
     * optional invocation-time branch override ({@code null} or blank when
     * none was supplied).
     */
    private record Scenario(RepositoryCoordinates commonsRepository, String overrideBranch) {
    }

    // Feature: test-server-factoring, Property 4: Commons branch selection honors the invocation override
    @Property(tries = 300)
    void commonsBranchSelectionHonorsTheInvocationOverride(@ForAll("scenarios") Scenario s) {
        CommonsOrigin origin = CommonsOrigin.select(s.commonsRepository(), s.overrideBranch());

        // The clone URL always passes through from the entry unchanged.
        assertEquals(s.commonsRepository().url(), origin.url(),
            "the commons clone URL must be the Commons_Configuration_Entry's url");

        boolean overrideSupplied =
            s.overrideBranch() != null && !s.overrideBranch().isBlank();
        if (overrideSupplied) {
            // The invocation override wins, with its reason.
            assertEquals(s.overrideBranch(), origin.branch(),
                "a supplied invocation override branch must be selected");
            assertEquals(ResolutionReason.INVOCATION_OVERRIDE, origin.reason(),
                "an override selection must carry reason invocation-override");
        } else {
            // With no override, the entry's branch applies, with its reason.
            assertEquals(s.commonsRepository().branch(), origin.branch(),
                "with no override, the Commons_Configuration_Entry branch must be selected");
            assertEquals(ResolutionReason.CONFIGURATION_ENTRY, origin.reason(),
                "an entry selection must carry reason configuration-entry");
        }
    }

    // ------------------------------------------------------------------
    // Generators
    // ------------------------------------------------------------------

    @Provide
    Arbitrary<Scenario> scenarios() {
        return Combinators.combine(commonsRepositories(), overrideBranches())
            .as(Scenario::new);
    }

    /** Complete Commons_Configuration_Entry coordinates with arbitrary url + branch. */
    private Arbitrary<RepositoryCoordinates> commonsRepositories() {
        Arbitrary<String> names = Arbitraries.of(
            "aws-crypto-tools-commons", "crypto-commons", "commons-mirror");
        Arbitrary<String> urls = branchNames().map(
            slug -> "git@github.com:aws/" + slug + ".git");
        return Combinators.combine(names, urls, branchNames())
            .as((name, url, branch) ->
                new RepositoryCoordinates(name, url, branch, RepositoryCoordinates.DEFAULT_PATH));
    }

    /**
     * Optional invocation-time overrides: absent ({@code null}), blank
     * (empty or whitespace-only — both count as "none supplied"), or a
     * non-blank branch name.
     */
    private Arbitrary<String> overrideBranches() {
        Arbitrary<String> blank = Arbitraries.strings()
            .withChars(' ', '\t', '\n').ofMinLength(0).ofMaxLength(4);
        return Arbitraries.oneOf(branchNames(), blank).injectNull(0.25);
    }

    /** Git-ish non-blank branch names, e.g. {@code kessplas/esdk-test-server}. */
    private Arbitrary<String> branchNames() {
        return Arbitraries.strings()
            .withCharRange('a', 'z').withCharRange('0', '9')
            .withChars('-', '.', '_', '/')
            .ofMinLength(1).ofMaxLength(30)
            .filter(s -> !s.isBlank());
    }
}
