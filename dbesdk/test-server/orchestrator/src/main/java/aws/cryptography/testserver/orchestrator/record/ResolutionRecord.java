package aws.cryptography.testserver.orchestrator.record;

import aws.cryptography.testserver.orchestrator.source.ComponentId;
import aws.cryptography.testserver.orchestrator.source.MaterializedSources;
import aws.cryptography.testserver.orchestrator.source.ResolutionReason;
import aws.cryptography.testserver.orchestrator.source.RunContext;
import aws.cryptography.testserver.orchestrator.source.SourcePlan;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

/**
 * The Resolution_Record of one orchestrated run (design "Resolution_Record",
 * Requirement 5): what source was resolved for every component and why.
 *
 * <p>Assembled from the run's {@link MaterializedSources} (one entry per
 * materialization outcome): one component per language library, one per
 * language server, plus the {@code commons} clone on Language_Repository_Runs
 * (Requirement 5.1). Successful components carry the repository, reference,
 * resolved commit, and reason (Requirements 5.1, 5.2); working-tree components
 * additionally carry the {@code dirty} flag (Requirement 5.7); failed
 * components are recorded with their attempted coordinates — path included for
 * server components — and cause (Requirement 5.4).
 *
 * <p><strong>Repository naming.</strong> The record reports each component's
 * {@code repository} as the repository <em>name</em>, matching the
 * Server_Location repository names in the Configuration_Set and the design's
 * example record. For clone components the name is derived from the clone
 * URL's final path segment with any {@code .git} suffix stripped (the plan
 * carries only the URL); for working-tree components it is the invoking
 * repository's canonical name from the {@link RunContext}. The full clone URL
 * of a failed clone remains visible in the failure {@code cause} produced by
 * the SourceMaterializer.
 *
 * <p>The record is a run gate, not just a log: {@link #completeness(Set)}
 * verifies every expected component is present with every required element
 * non-empty, and an unproducible or incomplete record must fail the run before
 * any Test executes (Requirement 5.5). The pipeline (task 9.1) emits the
 * record — {@link #toStdoutBlock()} to the run log and {@link #writeJson(Path)}
 * to {@link #DEFAULT_JSON_OUTPUT} — before the first Test executes and before
 * the run result is reported (Requirement 5.6).
 */
public final class ResolutionRecord {

    /**
     * The default JSON emission target, relative to the TestServer root
     * ({@code <sdk>/test-server/}) — colocated with the runner's other
     * scratch under {@code build/}. {@link #writeJson(Path)} takes the target
     * as an argument so the pipeline can resolve this default against the
     * actual invocation root.
     */
    public static final Path DEFAULT_JSON_OUTPUT =
        Path.of("build", "resolution-record.json");

    /** The {@code commons} component's canonical id in the record. */
    private static final String COMMONS_COMPONENT = ComponentId.commons().toString();

    /**
     * One successfully resolved component (design record {@code components[]}).
     *
     * @param component  the canonical component id: {@code library:<lang>},
     *                   {@code server:<lang>}, or {@code commons}
     * @param repository the repository name (see class note on naming)
     * @param reference  the reference the source stands at
     * @param commit     the resolved commit identifier (Requirement 5.1)
     * @param reason     why this source was chosen (Requirement 5.2)
     * @param path       the component path within the repository — recorded for
     *                   server components, {@code null} otherwise
     * @param dirty      whether the working tree carries uncommitted
     *                   modifications (Requirement 5.7) — {@code null} for
     *                   clone components
     */
    public record Component(
        String component,
        String repository,
        String reference,
        String commit,
        ResolutionReason reason,
        String path,
        Boolean dirty
    ) {
    }

    /**
     * One component that failed to resolve, with its attempted coordinates and
     * cause (design record {@code failures[]}, Requirement 5.4).
     *
     * @param component  the canonical component id
     * @param repository the attempted repository name
     * @param reference  the attempted reference — {@code null} for a working
     *                   tree (no reference was requested)
     * @param path       the attempted Server_Location path — recorded for
     *                   server components, {@code null} otherwise
     * @param cause      the failure cause
     */
    public record Failure(
        String component,
        String repository,
        String reference,
        String path,
        String cause
    ) {
    }

    /**
     * The structured outcome of the completeness check (Requirement 5.5):
     * {@code complete} iff the record contains every expected component with
     * every required element non-empty; otherwise {@code problems} names each
     * missing component or element.
     */
    public record Completeness(boolean complete, List<String> problems) {
        public Completeness {
            problems = List.copyOf(problems);
        }
    }

    private final RunContext.Kind kind;
    private final String runContext;
    private final List<Component> components;
    private final List<Failure> failures;

    public ResolutionRecord(
            RunContext.Kind kind,
            String runContext,
            List<Component> components,
            List<Failure> failures) {
        if (kind == null) {
            throw new IllegalArgumentException("kind is required");
        }
        if (runContext == null || runContext.isBlank()) {
            throw new IllegalArgumentException("runContext is required");
        }
        this.kind = kind;
        this.runContext = runContext;
        this.components = List.copyOf(components);
        this.failures = List.copyOf(failures);
    }

    /**
     * Assembles the record from the run's context and materialization
     * outcomes, one record entry per outcome in materialization order: every
     * {@link MaterializedSources.Success} becomes a {@link Component}, every
     * {@link MaterializedSources.Failure} a {@link Failure} (Requirements 5.1,
     * 5.2, 5.4, 5.7).
     */
    public static ResolutionRecord assemble(RunContext context, MaterializedSources sources) {
        String label = context.kind() == RunContext.Kind.COMMONS
            ? "commons"
            : "language:" + context.ownLanguage();
        List<Component> components = new ArrayList<>();
        List<Failure> failures = new ArrayList<>();
        for (MaterializedSources.Outcome outcome : sources.outcomes()) {
            String id = outcome.component().toString();
            boolean server = outcome.component().kind() == ComponentId.Kind.SERVER;
            switch (outcome) {
                case MaterializedSources.Success success -> components.add(new Component(
                    id,
                    repositoryOf(success.plan(), context),
                    success.reference(),
                    success.commit(),
                    success.reason(),
                    server ? pathOf(success.plan()) : null,
                    success.dirty()));
                case MaterializedSources.Failure failure -> failures.add(new Failure(
                    id,
                    repositoryOf(failure.plan(), context),
                    failure.attemptedReference(),
                    server ? failure.attemptedPath() : null,
                    failure.cause()));
            }
        }
        return new ResolutionRecord(context.kind(), label, components, failures);
    }

    /** The run-context label: {@code commons} or {@code language:<lang>}. */
    public String runContext() {
        return runContext;
    }

    /** The execution-context kind the record was assembled for. */
    public RunContext.Kind kind() {
        return kind;
    }

    /** The successfully resolved components, in materialization order. */
    public List<Component> components() {
        return components;
    }

    /** The components that failed to resolve, in materialization order. */
    public List<Failure> failures() {
        return failures;
    }

    /**
     * The run-gating completeness check (Requirement 5.5): given the run's
     * expected language set, verifies that every language's {@code library} and
     * {@code server} component is present (as a success or a recorded failure),
     * that the {@code commons} component is present exactly on
     * Language_Repository_Runs, that no component appears more than once, and
     * that every required element is non-empty — repository, reference, commit,
     * and reason on successes (path additionally for servers, the {@code dirty}
     * flag for working-tree components), repository and cause on failures (path
     * additionally for server failures).
     *
     * <p>A component recorded as a failure counts as present — Requirement 5.4
     * requires exactly that recording — but the materialization failure itself
     * gates the run separately (Requirement 3.6).
     */
    public Completeness completeness(Set<String> expectedLanguages) {
        if (expectedLanguages == null || expectedLanguages.isEmpty()) {
            throw new IllegalArgumentException("the expected language set is required");
        }
        List<String> problems = new ArrayList<>();

        Map<String, Integer> counts = new HashMap<>();
        components.forEach(c -> counts.merge(c.component(), 1, Integer::sum));
        failures.forEach(f -> counts.merge(f.component(), 1, Integer::sum));

        List<String> expected = new ArrayList<>();
        for (String language : new TreeSet<>(expectedLanguages)) {
            expected.add(ComponentId.library(language).toString());
            expected.add(ComponentId.server(language).toString());
        }
        if (kind == RunContext.Kind.LANGUAGE) {
            expected.add(COMMONS_COMPONENT);
        }
        for (String id : expected) {
            int count = counts.getOrDefault(id, 0);
            if (count == 0) {
                problems.add("missing component: " + id);
            } else if (count > 1) {
                problems.add("component recorded " + count + " times: " + id);
            }
        }
        if (kind == RunContext.Kind.COMMONS && counts.containsKey(COMMONS_COMPONENT)) {
            problems.add("unexpected commons component in a Commons_Run");
        }

        for (Component component : components) {
            String id = describe(component.component());
            requireNonBlank(problems, id, "component id", component.component());
            requireNonBlank(problems, id, "repository", component.repository());
            requireNonBlank(problems, id, "reference", component.reference());
            requireNonBlank(problems, id, "commit", component.commit());
            if (component.reason() == null) {
                problems.add(id + ": missing reason");
            }
            if (isServer(component.component())) {
                requireNonBlank(problems, id, "path", component.path());
            }
            if (component.reason() == ResolutionReason.WORKING_TREE && component.dirty() == null) {
                problems.add(id + ": working-tree component missing the dirty flag");
            }
        }
        for (Failure failure : failures) {
            String id = describe(failure.component()) + " (failure)";
            requireNonBlank(problems, id, "component id", failure.component());
            requireNonBlank(problems, id, "repository", failure.repository());
            requireNonBlank(problems, id, "cause", failure.cause());
            if (isServer(failure.component())) {
                requireNonBlank(problems, id, "path", failure.path());
            }
        }
        return new Completeness(problems.isEmpty(), problems);
    }

    /**
     * The record as the design's JSON document: {@code runContext},
     * {@code components[]} (with {@code path} for servers and {@code dirty} for
     * working trees), and {@code failures[]}. Reason values are the canonical
     * kebab-case labels ({@code configuration-entry} | {@code
     * configuration-override} | {@code working-tree} | {@code
     * invocation-override}).
     */
    public String toJson() {
        ObjectMapper mapper = new ObjectMapper();
        ObjectNode root = mapper.createObjectNode();
        root.put("runContext", runContext);
        ArrayNode componentsNode = root.putArray("components");
        for (Component component : components) {
            ObjectNode node = componentsNode.addObject();
            node.put("component", component.component());
            node.put("repository", component.repository());
            node.put("reference", component.reference());
            node.put("commit", component.commit());
            if (component.path() != null) {
                node.put("path", component.path());
            }
            node.put("reason", component.reason() == null ? null : component.reason().label());
            if (component.dirty() != null) {
                node.put("dirty", component.dirty());
            }
        }
        ArrayNode failuresNode = root.putArray("failures");
        for (Failure failure : failures) {
            ObjectNode node = failuresNode.addObject();
            node.put("component", failure.component());
            node.put("repository", failure.repository());
            if (failure.reference() != null) {
                node.put("reference", failure.reference());
            }
            if (failure.path() != null) {
                node.put("path", failure.path());
            }
            node.put("cause", failure.cause());
        }
        try {
            return mapper.writerWithDefaultPrettyPrinter().writeValueAsString(root);
        } catch (IOException e) {
            throw new IllegalStateException("could not serialize the Resolution_Record", e);
        }
    }

    /**
     * Writes {@link #toJson()} to {@code target}, creating parent directories
     * as needed. The pipeline passes {@link #DEFAULT_JSON_OUTPUT} resolved
     * against the invocation root.
     */
    public void writeJson(Path target) throws IOException {
        Path parent = target.getParent();
        if (parent != null) {
            Files.createDirectories(parent);
        }
        Files.writeString(target, toJson() + System.lineSeparator(), StandardCharsets.UTF_8);
    }

    /**
     * The record as a readable log block, emitted to the run's output before
     * the first Test executes and before the run result is reported
     * (Requirement 5.6).
     */
    public String toStdoutBlock() {
        StringBuilder block = new StringBuilder();
        block.append("==== Resolution_Record ====\n");
        block.append("runContext: ").append(runContext).append('\n');
        block.append("resolved components:").append(components.isEmpty() ? " none\n" : "\n");
        for (Component component : components) {
            block.append("  ").append(component.component())
                .append("  repository=").append(component.repository())
                .append("  reference=").append(component.reference())
                .append("  commit=").append(component.commit());
            if (component.path() != null) {
                block.append("  path=").append(component.path());
            }
            block.append("  reason=")
                .append(component.reason() == null ? "?" : component.reason().label());
            if (component.dirty() != null) {
                block.append("  dirty=").append(component.dirty());
            }
            block.append('\n');
        }
        block.append("failures:").append(failures.isEmpty() ? " none\n" : "\n");
        for (Failure failure : failures) {
            block.append("  ").append(failure.component())
                .append("  repository=").append(failure.repository());
            if (failure.reference() != null) {
                block.append("  reference=").append(failure.reference());
            }
            if (failure.path() != null) {
                block.append("  path=").append(failure.path());
            }
            block.append('\n');
            block.append("      cause: ").append(failure.cause()).append('\n');
        }
        block.append("===========================");
        return block.toString();
    }

    // ------------------------------------------------------------------
    // Assembly helpers
    // ------------------------------------------------------------------

    private static String repositoryOf(SourcePlan plan, RunContext context) {
        return switch (plan) {
            case SourcePlan.Clone clone -> repositoryNameFromUrl(clone.url());
            case SourcePlan.WorkingTree tree -> context.invokingRepositoryName();
        };
    }

    /**
     * The repository name a clone URL denotes: the final path segment with any
     * trailing slashes and {@code .git} suffix stripped, handling both
     * path-style ({@code https://…/org/name.git}) and scp-style
     * ({@code git@host:org/name.git}) URLs. Falls back to the URL itself when
     * no segment can be extracted.
     */
    static String repositoryNameFromUrl(String url) {
        String repository = url.replaceAll("/+$", "");
        int separator = Math.max(repository.lastIndexOf('/'), repository.lastIndexOf(':'));
        if (separator >= 0) {
            repository = repository.substring(separator + 1);
        }
        if (repository.endsWith(".git")) {
            repository = repository.substring(0, repository.length() - 4);
        }
        return repository.isBlank() ? url : repository;
    }

    private static String pathOf(SourcePlan plan) {
        return switch (plan) {
            case SourcePlan.Clone clone -> clone.path();
            case SourcePlan.WorkingTree tree -> tree.path();
        };
    }

    // ------------------------------------------------------------------
    // Completeness helpers
    // ------------------------------------------------------------------

    private static boolean isServer(String componentId) {
        return componentId != null && componentId.startsWith("server:");
    }

    private static String describe(String componentId) {
        return componentId == null || componentId.isBlank() ? "<unidentified component>"
            : componentId;
    }

    private static void requireNonBlank(
            List<String> problems, String id, String element, String value) {
        if (value == null || value.isBlank()) {
            problems.add(id + ": missing " + element);
        }
    }
}
