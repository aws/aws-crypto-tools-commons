package aws.cryptography.esdk.testserver.orchestrator.config;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

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
 * Property-based tests for {@link ConfigurationSet#validate()} using jqwik. Each
 * property runs a minimum of 100 generated iterations.
 *
 * <p>These run against the in-process validation unit only — no server is
 * launched (design Testing Strategy: P11 is orchestrator config-layer logic).
 */
class ConfigurationSetValidationPropertyTest {

    private static final List<String> LANG_POOL =
        List.of("java", "python", "javascript", "rust", "go", "dotnet");

    /** A fully valid entry for {@code language} at a distinct {@code port}. */
    private static ConfigurationEntry validEntry(String language, int port) {
        return new ConfigurationEntry(language, "main", "repo-" + language, 3, port);
    }

    private static List<ConfigurationEntry> validEntries(List<String> langs) {
        List<ConfigurationEntry> entries = new ArrayList<>();
        int port = 1024;
        for (String lang : langs) {
            entries.add(validEntry(lang, port++));
        }
        return entries;
    }

    // Feature: esdk-test-server, Property 11: Configuration_Set validation rejects invalid entries
    // Positive control: a well-formed set with unique ports validates.
    @Property(tries = 200, generation = GenerationMode.RANDOMIZED)
    void wellFormedUniquePortSetIsAccepted(@ForAll("languageSubsets") List<String> langs) {
        ConfigurationSetValidation v = new ConfigurationSet(validEntries(langs)).validate();
        assertTrue(v.valid(),
            "a well-formed set with unique ports must validate, but got: " + v.errors());
    }

    // Feature: esdk-test-server, Property 11: Configuration_Set validation rejects invalid entries
    @Property(tries = 200, generation = GenerationMode.RANDOMIZED)
    void malformedEntryIsRejectedAndIdentified(
            @ForAll("languageSubsets") List<String> langs,
            @ForAll("brokenField") String field,
            @ForAll @IntRange(min = 0, max = 5) int seed) {
        List<ConfigurationEntry> entries = validEntries(langs);
        int idx = Math.floorMod(seed, entries.size());
        ConfigurationEntry good = entries.get(idx);

        ConfigurationEntry broken;
        String expectedToken;
        String expectedIdentity;
        switch (field) {
            case "branch" -> {
                broken = new ConfigurationEntry(good.language(), "  ", good.repository(),
                    good.majorVersion(), good.port());
                expectedToken = "missing branch";
                expectedIdentity = good.language();
            }
            case "repository" -> {
                broken = new ConfigurationEntry(good.language(), good.branch(), null,
                    good.majorVersion(), good.port());
                expectedToken = "missing repository";
                expectedIdentity = good.language();
            }
            case "majorVersion" -> {
                broken = new ConfigurationEntry(good.language(), good.branch(), good.repository(),
                    0, good.port());
                expectedToken = "must be >= 1";
                expectedIdentity = good.language();
            }
            case "port" -> {
                broken = new ConfigurationEntry(good.language(), good.branch(), good.repository(),
                    good.majorVersion(), 70000);
                expectedToken = "out of range";
                expectedIdentity = good.language();
            }
            default -> { // "language"
                broken = new ConfigurationEntry("  ", good.branch(), good.repository(),
                    good.majorVersion(), good.port());
                expectedToken = "missing language";
                expectedIdentity = "<unnamed entry>";
            }
        }
        entries.set(idx, broken);

        ConfigurationSetValidation v = new ConfigurationSet(entries).validate();
        assertFalse(v.valid(), "a set containing a malformed entry must be rejected");
        assertTrue(v.message().contains(expectedToken),
            "error must describe the problem (" + expectedToken + "): " + v.errors());
        assertTrue(v.message().contains(expectedIdentity),
            "error must identify the offending entry (" + expectedIdentity + "): " + v.errors());
    }

    // Feature: esdk-test-server, Property 11: Configuration_Set validation rejects invalid entries
    @Property(tries = 200, generation = GenerationMode.RANDOMIZED)
    void duplicatePortsAreRejected(
            @ForAll("languageSubsetsMin2") List<String> langs,
            @ForAll @IntRange(min = 0, max = 5) int seed) {
        List<ConfigurationEntry> entries = validEntries(langs);
        int a = Math.floorMod(seed, entries.size());
        int b = (a + 1) % entries.size();
        // Force b to share a's port (a != b since size >= 2).
        ConfigurationEntry eb = entries.get(b);
        entries.set(b, new ConfigurationEntry(eb.language(), eb.branch(), eb.repository(),
            eb.majorVersion(), entries.get(a).port()));

        ConfigurationSetValidation v = new ConfigurationSet(entries).validate();
        assertFalse(v.valid(), "two entries sharing a port must be rejected");
        assertTrue(v.message().contains("share port"),
            "error must identify the shared port: " + v.errors());
    }

    @Provide
    Arbitrary<List<String>> languageSubsets() {
        return Arbitraries.subsetOf(LANG_POOL).ofMinSize(1).map(List::copyOf);
    }

    @Provide
    Arbitrary<List<String>> languageSubsetsMin2() {
        return Arbitraries.subsetOf(LANG_POOL).ofMinSize(2).map(List::copyOf);
    }

    @Provide
    Arbitrary<String> brokenField() {
        return Arbitraries.of("branch", "repository", "majorVersion", "port", "language");
    }
}
