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
 * Property-based tests for {@link ConfigurationValidation} using jqwik. Each
 * property runs a minimum of 100 generated iterations.
 *
 * <p>Contains the migrated legacy structural checks (per-entry fields and port
 * uniqueness) against the new validation entry point, plus the dedicated
 * test-server-factoring Property 1 test covering overrides and run contexts
 * ({@link #validationAcceptsExactlyTheWellFormedConfigurations}).
 *
 * <p>These run against the in-process validation unit only — no server is
 * launched and nothing is cloned (design "ConfigurationValidation": structural
 * validation must be able to run before anything is cloned).
 */
class ConfigurationSetValidationPropertyTest {

    private static final List<String> LANG_POOL =
        List.of("java", "python", "javascript", "rust", "go", "dotnet");

    private static final List<String> CATALOG = List.of("streaming", "MPL");

    /** A structurally complete entry for {@code language} at {@code port}. */
    private static ConfigurationEntry validEntry(String language, int port) {
        return new ConfigurationEntry(language, 3, port,
            new RepositoryCoordinates("repo-" + language,
                "git@github.com:aws/repo-" + language + ".git", "main", "."),
            new ServerLocation("aws-crypto-tools-commons",
                "git@github.com:aws/aws-crypto-tools-commons.git", "main",
                "esdk/test-server/servers/" + language),
            null, null);
    }

    private static List<ConfigurationEntry> validEntries(List<String> langs) {
        List<ConfigurationEntry> entries = new ArrayList<>();
        int port = 1024;
        for (String lang : langs) {
            entries.add(validEntry(lang, port++));
        }
        return entries;
    }

    private static ConfigurationSetValidation validate(List<ConfigurationEntry> entries) {
        return ConfigurationValidation.validate(
            new ConfigurationSet("esdk", CATALOG, entries), List.of(), null);
    }

    /** Rebuild {@code e} with a replacement library repository. */
    private static ConfigurationEntry withLibrary(ConfigurationEntry e, RepositoryCoordinates lib) {
        return new ConfigurationEntry(e.language(), e.majorVersion(), e.port(),
            lib, e.serverLocation(), e.supportedFeatures(), e.unsupportedFeatures());
    }

    /** Rebuild {@code e} with a replacement Server_Location. */
    private static ConfigurationEntry withServerLocation(ConfigurationEntry e, ServerLocation loc) {
        return new ConfigurationEntry(e.language(), e.majorVersion(), e.port(),
            e.libraryRepository(), loc, e.supportedFeatures(), e.unsupportedFeatures());
    }

    // Feature: esdk-test-server, Property 11: Configuration_Set validation rejects invalid entries
    // Positive control: a well-formed set with unique ports validates.
    @Property(tries = 200, generation = GenerationMode.RANDOMIZED)
    void wellFormedUniquePortSetIsAccepted(@ForAll("languageSubsets") List<String> langs) {
        ConfigurationSetValidation v = validate(validEntries(langs));
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
        RepositoryCoordinates lib = good.libraryRepository();

        ConfigurationEntry broken;
        String expectedToken;
        String expectedIdentity;
        switch (field) {
            case "branch" -> {
                broken = withLibrary(good,
                    new RepositoryCoordinates(lib.name(), lib.url(), "  ", lib.path()));
                expectedToken = "libraryRepository missing branch";
                expectedIdentity = good.language();
            }
            case "repository" -> {
                broken = withLibrary(good,
                    new RepositoryCoordinates(null, lib.url(), lib.branch(), lib.path()));
                expectedToken = "libraryRepository missing name";
                expectedIdentity = good.language();
            }
            case "majorVersion" -> {
                broken = new ConfigurationEntry(good.language(), 0, good.port(),
                    lib, good.serverLocation(), null, null);
                expectedToken = "must be >= 1";
                expectedIdentity = good.language();
            }
            case "port" -> {
                broken = new ConfigurationEntry(good.language(), good.majorVersion(), 70000,
                    lib, good.serverLocation(), null, null);
                expectedToken = "out of range";
                expectedIdentity = good.language();
            }
            default -> { // "language"
                broken = new ConfigurationEntry("  ", good.majorVersion(), good.port(),
                    lib, good.serverLocation(), null, null);
                expectedToken = "missing language";
                expectedIdentity = "<unnamed entry>";
            }
        }
        entries.set(idx, broken);

        ConfigurationSetValidation v = validate(entries);
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
        entries.set(b, new ConfigurationEntry(eb.language(), eb.majorVersion(),
            entries.get(a).port(), eb.libraryRepository(), eb.serverLocation(), null, null));

        ConfigurationSetValidation v = validate(entries);
        assertFalse(v.valid(), "two entries sharing a port must be rejected");
        assertTrue(v.message().contains("share port"),
            "error must identify the shared port: " + v.errors());
    }

    // Feature: test-server-factoring, Property 1: Configuration validation accepts exactly the well-formed configurations
    //
    // For any generated Configuration_Set and optional Configuration_Overrides
    // in any run context (Commons_Run: ownLanguage null; Language_Repository_Run:
    // ownLanguage set): validation succeeds iff every entry and every override
    // has a non-empty language, majorVersion >= 1, a port in 1..65535 unique
    // across the effective set, a complete libraryRepository (name, url, branch)
    // and a complete Server_Location (repository, ref, path); every override
    // names a language that has a commons-stored entry and is not the run's own
    // language. Every failure names the offending language and each
    // missing/invalid element. "No repository is obtained when validation
    // fails" holds by construction: ConfigurationValidation is a pure function
    // with no I/O, run by the pipeline before anything is cloned.
    //
    // Validates: Requirements 3.1, 3.2, 3.8, 4.7, 4.11
    @Property(tries = 300, generation = GenerationMode.RANDOMIZED)
    void validationAcceptsExactlyTheWellFormedConfigurations(
            @ForAll("languageSubsetsMin2") List<String> langs,
            @ForAll boolean languageRunRequested,
            @ForAll boolean includeValidOverride,
            @ForAll @IntRange(min = 0, max = 5) int ownSeed,
            @ForAll @IntRange(min = 0, max = 5) int targetSeed,
            @ForAll("property1Mutations") String mutation) {

        // Run context: Commons_Run (ownLanguage null) or Language_Repository_Run
        // (ownLanguage one of the configured languages). The own-language
        // override mutation only exists in a Language_Repository_Run.
        boolean languageRun = languageRunRequested || mutation.equals("override-own-language");
        String ownLanguage = languageRun ? langs.get(Math.floorMod(ownSeed, langs.size())) : null;

        List<ConfigurationEntry> entries = validEntries(langs);

        // The mutation/override target: any language other than the run's own.
        List<String> otherLangs = new ArrayList<>(langs);
        if (ownLanguage != null) {
            otherLangs.remove(ownLanguage);
        }
        String target = otherLangs.get(Math.floorMod(targetSeed, otherLangs.size()));
        int targetIdx = langs.indexOf(target);
        ConfigurationEntry targetEntry = entries.get(targetIdx);

        // Fresh port for override entries: base entry ports start at 1024 and
        // there are at most 6 entries, so 9001 never collides.
        int freshPort = 9001;

        List<ConfigurationEntry> overrides = new ArrayList<>();
        List<String> expectedTokens = new ArrayList<>();
        boolean expectValid = false;

        switch (mutation) {
            case "none" -> {
                expectValid = true;
                if (includeValidOverride) {
                    // A well-formed override of a commons-stored Other language
                    // is accepted in both run contexts.
                    overrides.add(validEntry(target, freshPort));
                }
            }
            case "entry-language" -> {
                entries.set(targetIdx, new ConfigurationEntry("  ",
                    targetEntry.majorVersion(), targetEntry.port(),
                    targetEntry.libraryRepository(), targetEntry.serverLocation(), null, null));
                expectedTokens.add("missing language");
                expectedTokens.add("<unnamed entry>");
            }
            case "entry-major" -> {
                entries.set(targetIdx, new ConfigurationEntry(target, 0, targetEntry.port(),
                    targetEntry.libraryRepository(), targetEntry.serverLocation(), null, null));
                expectedTokens.add(target);
                expectedTokens.add("must be >= 1");
            }
            case "entry-port-range" -> {
                entries.set(targetIdx, new ConfigurationEntry(target,
                    targetEntry.majorVersion(), 70000,
                    targetEntry.libraryRepository(), targetEntry.serverLocation(), null, null));
                expectedTokens.add(target);
                expectedTokens.add("out of range");
            }
            case "entry-lib-null" -> {
                entries.set(targetIdx, withLibrary(targetEntry, null));
                expectedTokens.add(target);
                expectedTokens.add("missing libraryRepository");
            }
            case "entry-lib-name" -> {
                RepositoryCoordinates lib = targetEntry.libraryRepository();
                entries.set(targetIdx, withLibrary(targetEntry,
                    new RepositoryCoordinates("  ", lib.url(), lib.branch(), lib.path())));
                expectedTokens.add(target);
                expectedTokens.add("libraryRepository missing name");
            }
            case "entry-lib-url" -> {
                RepositoryCoordinates lib = targetEntry.libraryRepository();
                entries.set(targetIdx, withLibrary(targetEntry,
                    new RepositoryCoordinates(lib.name(), null, lib.branch(), lib.path())));
                expectedTokens.add(target);
                expectedTokens.add("libraryRepository missing url");
            }
            case "entry-lib-branch" -> {
                RepositoryCoordinates lib = targetEntry.libraryRepository();
                entries.set(targetIdx, withLibrary(targetEntry,
                    new RepositoryCoordinates(lib.name(), lib.url(), "  ", lib.path())));
                expectedTokens.add(target);
                expectedTokens.add("libraryRepository missing branch");
            }
            case "entry-loc-null" -> {
                entries.set(targetIdx, withServerLocation(targetEntry, null));
                expectedTokens.add(target);
                expectedTokens.add("missing serverLocation");
            }
            case "entry-loc-repository" -> {
                ServerLocation loc = targetEntry.serverLocation();
                entries.set(targetIdx, withServerLocation(targetEntry,
                    new ServerLocation(null, loc.url(), loc.ref(), loc.path())));
                expectedTokens.add(target);
                expectedTokens.add("serverLocation missing repository");
            }
            case "entry-loc-ref" -> {
                ServerLocation loc = targetEntry.serverLocation();
                entries.set(targetIdx, withServerLocation(targetEntry,
                    new ServerLocation(loc.repository(), loc.url(), "  ", loc.path())));
                expectedTokens.add(target);
                expectedTokens.add("serverLocation missing ref");
            }
            case "entry-loc-path" -> {
                ServerLocation loc = targetEntry.serverLocation();
                entries.set(targetIdx, withServerLocation(targetEntry,
                    new ServerLocation(loc.repository(), loc.url(), loc.ref(), null)));
                expectedTokens.add(target);
                expectedTokens.add("serverLocation missing path");
            }
            case "dup-port-entries" -> {
                // Two stored entries share a port (no overrides so the
                // collision survives into the effective set).
                int otherIdx = (targetIdx + 1) % langs.size();
                ConfigurationEntry other = entries.get(otherIdx);
                entries.set(otherIdx, new ConfigurationEntry(other.language(),
                    other.majorVersion(), targetEntry.port(),
                    other.libraryRepository(), other.serverLocation(), null, null));
                expectedTokens.add("share port");
                expectedTokens.add(target);
                expectedTokens.add(other.language());
            }
            case "dup-port-override" -> {
                // Port uniqueness holds across the EFFECTIVE set: a well-formed
                // override whose port collides with a non-overridden stored
                // entry's port is rejected.
                int otherIdx = (targetIdx + 1) % langs.size();
                ConfigurationEntry other = entries.get(otherIdx);
                overrides.add(validEntry(target, other.port()));
                expectedTokens.add("share port");
                expectedTokens.add(target);
                expectedTokens.add(other.language());
            }
            case "override-loc-ref" -> {
                // Overrides are validated structurally exactly like entries.
                ConfigurationEntry o = validEntry(target, freshPort);
                ServerLocation loc = o.serverLocation();
                overrides.add(withServerLocation(o,
                    new ServerLocation(loc.repository(), loc.url(), null, loc.path())));
                expectedTokens.add("override " + target);
                expectedTokens.add("serverLocation missing ref");
            }
            case "override-own-language" -> {
                // Requirement 4.7: an override must not name the run's own language.
                overrides.add(validEntry(ownLanguage, freshPort));
                expectedTokens.add("must not name the run's own language");
                expectedTokens.add(ownLanguage);
            }
            case "override-unknown-language" -> {
                // Requirement 4.11: an override must name a commons-stored language.
                overrides.add(validEntry("ruby", freshPort));
                expectedTokens.add("no commons-stored Configuration_Entry");
                expectedTokens.add("ruby");
            }
            default -> throw new IllegalStateException("unhandled mutation: " + mutation);
        }

        ConfigurationSetValidation v = ConfigurationValidation.validate(
            new ConfigurationSet("esdk", CATALOG, entries), overrides, ownLanguage);

        if (expectValid) {
            assertTrue(v.valid(), "a well-formed configuration (context="
                + (languageRun ? "language:" + ownLanguage : "commons")
                + ", overrides=" + overrides.size()
                + ") must validate, but got: " + v.errors());
        } else {
            assertFalse(v.valid(),
                "mutation '" + mutation + "' must be rejected (context="
                + (languageRun ? "language:" + ownLanguage : "commons") + ")");
            for (String token : expectedTokens) {
                assertTrue(v.message().contains(token),
                    "mutation '" + mutation + "': failure must name '" + token
                    + "', but got: " + v.errors());
            }
        }
    }

    @Provide
    Arbitrary<String> property1Mutations() {
        return Arbitraries.of(
            "none",
            "entry-language", "entry-major", "entry-port-range",
            "entry-lib-null", "entry-lib-name", "entry-lib-url", "entry-lib-branch",
            "entry-loc-null", "entry-loc-repository", "entry-loc-ref", "entry-loc-path",
            "dup-port-entries", "dup-port-override",
            "override-loc-ref", "override-own-language", "override-unknown-language");
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
