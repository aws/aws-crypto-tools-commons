package aws.cryptography.esdk.testserver.orchestrator.source;

import aws.cryptography.esdk.testserver.orchestrator.config.ConfigurationEntry;
import aws.cryptography.esdk.testserver.orchestrator.config.ConfigurationSet;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Maps each {@link ConfigurationEntry} plus the invocation's overrides to one
 * effective {@link ResolvedSource} (design "Source Resolution and Build
 * Strategy"). This is a <em>pure function</em> over its inputs — it neither
 * clones repositories nor touches the filesystem — so the pure-logic property
 * tests (Properties 12 and 13) run it in-process without launching servers.
 *
 * <p>Resolution rules:
 * <ul>
 *   <li>No override for a language → head of its configured branch/repository
 *       (Requirements 10.1, 10.2).</li>
 *   <li>Exactly one {@code Live} language → that language live, all Others at head
 *       unless individually overridden (Requirements 11.1, 12.5).</li>
 *   <li>{@code Submodule}/{@code Artifact} override → the referenced commit /
 *       artifact for that language (Requirements 12.4, 12.7).</li>
 *   <li>More than one {@code Live} language → abort, run no {@code Tests}
 *       (Requirement 11.5).</li>
 *   <li>More than one mode for one language → abort, run no {@code Tests}
 *       (Requirement 12.9).</li>
 * </ul>
 *
 * <p>Whether a resolved reference actually exists / builds (Requirements 10.4,
 * 11.4, 12.8) is decided later by the builder/launcher, not here; keeping I/O out
 * of this mapping is what makes it a pure function.
 */
public final class SourceResolver {

    /** Resolve every configured language to its effective source. */
    public SourceResolution resolve(ConfigurationSet set, List<Override> overrides) {
        // Group overrides by language, detecting >1 mode for one language
        // (Requirement 12.9) and >1 live language (Requirement 11.5).
        Map<String, Override> byLanguage = new LinkedHashMap<>();
        List<String> liveLanguages = new ArrayList<>();
        for (Override o : overrides) {
            String lang = o.language();
            if (byLanguage.containsKey(lang)) {
                return SourceResolution.failed(
                    "more than one consumption mode specified for language " + lang
                        + " (Requirement 12.9)");
            }
            byLanguage.put(lang, o);
            if (o instanceof Override.Live) {
                liveLanguages.add(lang);
            }
        }
        if (liveLanguages.size() > 1) {
            return SourceResolution.failed(
                "live source provided for more than one language " + liveLanguages
                    + " (Requirement 11.5)");
        }

        // Every override must reference a language present in the Configuration_Set.
        for (String lang : byLanguage.keySet()) {
            if (set.forLanguage(lang) == null) {
                return SourceResolution.failed(
                    "override references language " + lang
                        + " which has no Configuration_Entry");
            }
        }

        // Map each configured language to its single effective source.
        Map<String, ResolvedSource> resolved = new LinkedHashMap<>();
        for (ConfigurationEntry entry : set.entries()) {
            String lang = entry.language();
            Override o = byLanguage.get(lang);
            resolved.put(lang, effectiveSource(entry, o));
        }
        return SourceResolution.resolved(resolved);
    }

    private ResolvedSource effectiveSource(ConfigurationEntry entry, Override o) {
        if (o == null) {
            // Default: head of the configured branch/repository (Requirement 10.1).
            return new ResolvedSource.Head(entry.branch(), entry.repository());
        }
        return switch (o) {
            case Override.Live live -> new ResolvedSource.Live(live.path());
            case Override.Submodule sub -> new ResolvedSource.Submodule(sub.commit());
            case Override.Artifact art -> new ResolvedSource.Artifact(art.version());
        };
    }
}
