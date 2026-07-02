package aws.cryptography.esdk.testserver.orchestrator.source;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;

import aws.cryptography.esdk.testserver.orchestrator.config.ConfigurationEntry;
import aws.cryptography.esdk.testserver.orchestrator.config.ConfigurationSet;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import net.jqwik.api.Arbitraries;
import net.jqwik.api.Arbitrary;
import net.jqwik.api.Combinators;
import net.jqwik.api.ForAll;
import net.jqwik.api.GenerationMode;
import net.jqwik.api.Property;
import net.jqwik.api.Provide;

/**
 * Property-based test for {@link SourceResolver} using jqwik. Each property runs
 * a minimum of 100 generated iterations against the in-process resolver — a pure
 * function over overrides, so no server is launched and no repository is cloned
 * (design Testing Strategy: P12 is orchestrator resolver logic).
 */
class SourceResolutionPropertyTest {

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

    // Feature: esdk-test-server, Property 12: Source resolution maps each language to its effective source
    @Property(tries = 200, generation = GenerationMode.RANDOMIZED)
    void eachLanguageResolvesToItsEffectiveSource(@ForAll("invocation") Invocation inv) {
        ConfigurationSet set = setOf(inv.languages);
        SourceResolution resolution = resolver.resolve(set, inv.overrides);

        assertTrue(resolution.isResolved(),
            "a conflict-free invocation must resolve, but failed: " + resolution.failure());
        Map<String, ResolvedSource> sources = resolution.sources();
        assertEquals(inv.languages.size(), sources.size(),
            "every configured language must resolve to exactly one source");

        // Build the expected override-by-language view.
        Map<String, Override> expected = new java.util.HashMap<>();
        for (Override o : inv.overrides) {
            expected.put(o.language(), o);
        }

        for (String lang : inv.languages) {
            ResolvedSource resolved = sources.get(lang);
            Override o = expected.get(lang);
            if (o == null) {
                // No override -> head of the configured branch/repository (Req 10.1, 10.2).
                ResolvedSource.Head head = assertInstanceOf(ResolvedSource.Head.class, resolved,
                    lang + " without an override must resolve to head");
                assertEquals("main", head.branch());
                assertEquals("repo-" + lang, head.repository());
            } else if (o instanceof Override.Live live) {
                ResolvedSource.Live got = assertInstanceOf(ResolvedSource.Live.class, resolved,
                    lang + " with a live override must resolve to live");
                assertEquals(live.path(), got.path());
            } else if (o instanceof Override.Submodule sub) {
                ResolvedSource.Submodule got = assertInstanceOf(ResolvedSource.Submodule.class, resolved,
                    lang + " with a submodule override must resolve to the referenced commit");
                assertEquals(sub.commit(), got.commit());
            } else if (o instanceof Override.Artifact art) {
                ResolvedSource.Artifact got = assertInstanceOf(ResolvedSource.Artifact.class, resolved,
                    lang + " with an artifact override must resolve to that artifact");
                assertEquals(art.version(), got.version());
            }
        }
    }

    /** A conflict-free invocation: >=1 language, at most one override per language, at most one live. */
    record Invocation(List<String> languages, List<Override> overrides) {
    }

    @Provide
    Arbitrary<Invocation> invocation() {
        Arbitrary<List<String>> langs = Arbitraries.subsetOf(LANG_POOL).ofMinSize(1).map(List::copyOf);
        return langs.flatMap(languages -> {
            // Choose the live language index in [-1, size): -1 means no live language.
            Arbitrary<Integer> liveIndex = Arbitraries.integers().between(-1, languages.size() - 1);
            // For every language choose a non-live mode: 0=none, 1=submodule, 2=artifact.
            Arbitrary<List<Integer>> modes =
                Arbitraries.integers().between(0, 2).list().ofSize(languages.size());
            return Combinators.combine(liveIndex, modes).as((live, modeList) -> {
                List<Override> overrides = new ArrayList<>();
                for (int i = 0; i < languages.size(); i++) {
                    String lang = languages.get(i);
                    if (i == live) {
                        overrides.add(new Override.Live(lang, Path.of("/live/" + lang)));
                        continue;
                    }
                    switch (modeList.get(i)) {
                        case 1 -> overrides.add(new Override.Submodule(lang, "commit-" + lang));
                        case 2 -> overrides.add(new Override.Artifact(lang, "1." + i + ".0"));
                        default -> { /* no override -> head */ }
                    }
                }
                return new Invocation(languages, overrides);
            });
        });
    }
}
