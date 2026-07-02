package aws.cryptography.esdk.testserver.orchestrator.source;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import aws.cryptography.esdk.testserver.orchestrator.config.ConfigurationEntry;
import aws.cryptography.esdk.testserver.orchestrator.config.ConfigurationSet;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import net.jqwik.api.Arbitraries;
import net.jqwik.api.Arbitrary;
import net.jqwik.api.ForAll;
import net.jqwik.api.GenerationMode;
import net.jqwik.api.Property;
import net.jqwik.api.Provide;
import net.jqwik.api.constraints.IntRange;

/**
 * Property-based test for {@link SourceResolver}'s conflict detection using
 * jqwik (Property 13). Each property runs a minimum of 100 generated iterations
 * against the pure in-process resolver — no servers, no cloning.
 */
class ConflictingInputsPropertyTest {

    private static final List<String> LANG_POOL =
        List.of("java", "python", "javascript", "rust", "go", "dotnet");

    private final SourceResolver resolver = new SourceResolver();

    private static ConfigurationSet setOf(List<String> langs) {
        List<ConfigurationEntry> entries = new ArrayList<>();
        int port = 1024;
        for (String lang : langs) {
            entries.add(new ConfigurationEntry(lang, "main", "repo-" + lang, 3, port++));
        }
        return new ConfigurationSet(entries);
    }

    private Override anyModeFor(String lang, int mode) {
        return switch (mode) {
            case 0 -> new Override.Live(lang, Path.of("/live/" + lang));
            case 1 -> new Override.Submodule(lang, "commit-" + lang);
            default -> new Override.Artifact(lang, "1.0.0");
        };
    }

    // Feature: esdk-test-server, Property 13: Conflicting consumption inputs abort the run
    // Case A: live source for more than one language (Requirement 11.5).
    @Property(tries = 200, generation = GenerationMode.RANDOMIZED)
    void multipleLiveLanguagesAbort(@ForAll("languageSubsetsMin2") List<String> langs) {
        ConfigurationSet set = setOf(langs);
        List<Override> overrides = new ArrayList<>();
        // Make at least the first two languages live.
        overrides.add(new Override.Live(langs.get(0), Path.of("/live/" + langs.get(0))));
        overrides.add(new Override.Live(langs.get(1), Path.of("/live/" + langs.get(1))));

        SourceResolution resolution = resolver.resolve(set, overrides);
        assertFalse(resolution.isResolved(),
            "more than one live language must abort the run (Requirement 11.5)");
        assertTrue(resolution.sources().isEmpty(), "an aborted run resolves no sources");
    }

    // Feature: esdk-test-server, Property 13: Conflicting consumption inputs abort the run
    // Case B: more than one consumption mode for a single language (Requirement 12.9).
    @Property(tries = 200, generation = GenerationMode.RANDOMIZED)
    void multipleModesForOneLanguageAbort(
            @ForAll("languageSubsets") List<String> langs,
            @ForAll @IntRange(min = 0, max = 2) int modeA,
            @ForAll @IntRange(min = 0, max = 2) int modeB,
            @ForAll @IntRange(min = 0, max = 5) int seed) {
        ConfigurationSet set = setOf(langs);
        String lang = langs.get(Math.floorMod(seed, langs.size()));
        List<Override> overrides = new ArrayList<>();
        overrides.add(anyModeFor(lang, modeA));
        overrides.add(anyModeFor(lang, modeB));

        SourceResolution resolution = resolver.resolve(set, overrides);
        assertFalse(resolution.isResolved(),
            "more than one mode for one language must abort the run (Requirement 12.9)");
        assertTrue(resolution.sources().isEmpty(), "an aborted run resolves no sources");
    }

    @Provide
    Arbitrary<List<String>> languageSubsets() {
        return Arbitraries.subsetOf(LANG_POOL).ofMinSize(1).map(List::copyOf);
    }

    @Provide
    Arbitrary<List<String>> languageSubsetsMin2() {
        return Arbitraries.subsetOf(LANG_POOL).ofMinSize(2).map(List::copyOf);
    }
}
