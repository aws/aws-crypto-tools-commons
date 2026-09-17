package aws.cryptography.esdk.testserver.orchestrator.source;

import aws.cryptography.esdk.testserver.orchestrator.config.ConfigurationEntry;
import aws.cryptography.esdk.testserver.orchestrator.config.ConfigurationSet;
import aws.cryptography.esdk.testserver.orchestrator.config.RepositoryCoordinates;
import aws.cryptography.esdk.testserver.orchestrator.config.ServerLocation;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * The pure source-resolution planner (design "SourceResolver" and the
 * "Execution-context resolution rules" table): maps the effective configuration
 * — the commons-stored {@link ConfigurationSet} with each overridden language's
 * entry replaced by its Configuration_Override (Requirement 4.6) — plus the
 * {@link RunContext} to one {@link ResolvedComponentPlan} per
 * (language × {library, server}), plus the {@code commons} component on
 * Language_Repository_Runs. No I/O, no git: executing the plans is the
 * SourceMaterializer's job (task 3.1).
 *
 * <p>The rules, per the design table:
 * <ul>
 *   <li><b>Own language</b> (Language_Repository_Run only): library and server
 *       both plan the working tree at {@code languageRepoRoot} plus the
 *       configured paths, reason {@code working-tree}; the Server_Location ref
 *       is ignored and no clone is planned (Requirements 4.2, 3.4).</li>
 *   <li><b>Other language, no override</b>: the commons-stored entry — the
 *       working tree's Configuration_Set in a Commons_Run (Requirement 4.1),
 *       the commons clone's in a Language_Repository_Run (Requirement 4.3) —
 *       reason {@code configuration-entry}.</li>
 *   <li><b>Other language, override present</b>: every coordinate derives
 *       solely from the Configuration_Override (full replacement,
 *       Requirement 4.6), reason {@code configuration-override}.</li>
 *   <li><b>Server_Location naming the invoking repository</b>: a working-tree
 *       plan at the invocation's working tree root plus the location's path —
 *       no separate copy is obtained (Requirement 3.4).</li>
 *   <li><b>Server_Location naming any other repository</b>: a clone plan at
 *       exactly {@code (url, ref)} with the location's path
 *       (Requirement 3.3).</li>
 *   <li><b>Commons itself</b>: implicit (the working tree) in a Commons_Run; a
 *       clone plan at the {@link CommonsOrigin} coordinates in a
 *       Language_Repository_Run, whose branch and reason were selected by
 *       {@link CommonsOrigin#select} (Requirements 4.5, 4.8).</li>
 * </ul>
 *
 * <p>The run-effective Server_Location is the <em>sole</em> source planned for
 * a language's server — there is no other lookup path (Requirements 1.5, 3.5).
 *
 * <p>Inputs are assumed structurally valid: {@code ConfigurationValidation}
 * (own-language / unknown-language override rejection included) runs before
 * this planner, so the pipeline halts on malformed configuration before any
 * plan is produced (Requirement 3.8).
 */
public final class SourceResolver {

    /**
     * Plan every component of the run.
     *
     * @param set       the commons-stored Configuration_Set resolved for the run
     * @param context   the execution context
     * @param overrides the invoking Language_Repository's
     *                  Configuration_Overrides (empty for a Commons_Run), each a
     *                  complete replacement entry (Requirement 4.6)
     * @return one plan per (language × {library, server}) in entry order, with
     *     the {@code commons} component first on Language_Repository_Runs
     */
    public List<ResolvedComponentPlan> resolve(
            ConfigurationSet set, RunContext context, List<ConfigurationEntry> overrides) {
        return resolve(set, context, overrides, Map.of());
    }

    /**
     * Plan every component of the run, honoring a dev-only local-overrides
     * overlay.
     *
     * @param set                the commons-stored Configuration_Set resolved for the run
     * @param context            the execution context
     * @param overrides          the invoking Language_Repository's
     *                           Configuration_Overrides (empty for a Commons_Run),
     *                           each a complete replacement entry (Requirement 4.6)
     * @param localRepositories  a dev-only overlay mapping a language to a local
     *                           working-tree root; that language's library and
     *                           server are planned as {@link SourcePlan.WorkingTree}
     *                           at the root plus the effective entry's paths rather
     *                           than cloned. Ignored for the own language of a
     *                           Language_Repository_Run (already a working tree).
     *                           Empty in a normal (CI) run.
     * @return one plan per (language × {library, server}) in entry order, with
     *     the {@code commons} component first on Language_Repository_Runs
     */
    public List<ResolvedComponentPlan> resolve(
            ConfigurationSet set, RunContext context, List<ConfigurationEntry> overrides,
            Map<String, Path> localRepositories) {
        Map<String, ConfigurationEntry> overrideByLanguage = new LinkedHashMap<>();
        for (ConfigurationEntry override : overrides) {
            overrideByLanguage.put(override.language(), override);
        }

        List<ResolvedComponentPlan> plans = new ArrayList<>();

        // Commons itself: implicit working tree in a Commons_Run; the clone at
        // the selected branch in a Language_Repository_Run (Req 4.5, 4.8).
        if (context.kind() == RunContext.Kind.LANGUAGE) {
            CommonsOrigin origin = context.commonsOrigin();
            plans.add(new ResolvedComponentPlan(
                ComponentId.commons(),
                new SourcePlan.Clone(origin.url(), origin.branch(),
                    RepositoryCoordinates.DEFAULT_PATH),
                origin.reason()));
        }

        for (ConfigurationEntry stored : set.entries()) {
            String language = stored.language();
            boolean ownLanguage = context.kind() == RunContext.Kind.LANGUAGE
                && language.equals(context.ownLanguage());

            // Full-replacement override semantics (Req 4.6): the overridden
            // language resolves solely from its override. The own language never
            // has one — ConfigurationValidation rejects it (Req 4.7).
            ConfigurationEntry override = ownLanguage ? null : overrideByLanguage.get(language);
            ConfigurationEntry effective = override != null ? override : stored;

            // A dev-only local override wins over a clone (but never over the
            // own language, which is already a working tree). It replaces only
            // the source location; the component paths still come from the
            // effective entry.
            Path localRoot = ownLanguage ? null : localRepositories.get(language);

            ResolutionReason reason = ownLanguage
                ? ResolutionReason.WORKING_TREE
                : localRoot != null
                    ? ResolutionReason.LOCAL_OVERRIDE
                    : override != null
                        ? ResolutionReason.CONFIGURATION_OVERRIDE
                        : ResolutionReason.CONFIGURATION_ENTRY;

            plans.add(libraryPlan(language, effective, context, ownLanguage, localRoot, reason));
            plans.add(serverPlan(language, effective, context, ownLanguage, localRoot, reason));
        }
        return List.copyOf(plans);
    }

    /**
     * The library component: the own language's working tree in a
     * Language_Repository_Run (Requirement 4.2), a dev-only local working tree
     * when {@code localRoot} is set, otherwise a clone of the run-effective
     * library repository coordinates (Requirements 4.1, 4.3, 4.6).
     */
    private static ResolvedComponentPlan libraryPlan(
            String language, ConfigurationEntry effective, RunContext context,
            boolean ownLanguage, Path localRoot, ResolutionReason reason) {
        RepositoryCoordinates library = effective.libraryRepository();
        String path = pathOrDefault(library == null ? null : library.path());
        SourcePlan plan;
        if (ownLanguage) {
            plan = new SourcePlan.WorkingTree(context.languageRepoRoot(), path);
        } else if (localRoot != null) {
            plan = new SourcePlan.WorkingTree(localRoot, path);
        } else {
            plan = new SourcePlan.Clone(library.url(), library.branch(), path);
        }
        return new ResolvedComponentPlan(ComponentId.library(language), plan, reason);
    }

    /**
     * The server component, from the run-effective Server_Location as the sole
     * source (Requirements 1.5, 3.5): the own language's working tree
     * (Requirement 4.2, ref ignored); a dev-only local working tree when
     * {@code localRoot} is set; a working-tree plan when the Server_Location
     * names the invoking repository (Requirement 3.4); a clone at exactly
     * {@code (url, ref)} with the location's path otherwise (Requirement 3.3).
     */
    private static ResolvedComponentPlan serverPlan(
            String language, ConfigurationEntry effective, RunContext context,
            boolean ownLanguage, Path localRoot, ResolutionReason reason) {
        ServerLocation location = effective.serverLocation();
        String path = pathOrDefault(location == null ? null : location.path());
        SourcePlan plan;
        if (ownLanguage) {
            plan = new SourcePlan.WorkingTree(context.languageRepoRoot(), path);
        } else if (localRoot != null) {
            plan = new SourcePlan.WorkingTree(localRoot, path);
        } else if (location.repository().equals(context.invokingRepositoryName())) {
            plan = new SourcePlan.WorkingTree(context.invokingWorkingTreeRoot(), path);
        } else {
            plan = new SourcePlan.Clone(location.url(), location.ref(), path);
        }
        return new ResolvedComponentPlan(ComponentId.server(language), plan, reason);
    }

    private static String pathOrDefault(String path) {
        return (path == null || path.isBlank()) ? RepositoryCoordinates.DEFAULT_PATH : path;
    }
}
