package aws.cryptography.esdk.testserver.orchestrator;

import aws.cryptography.esdk.testserver.orchestrator.config.ConfigurationSet;
import aws.cryptography.esdk.testserver.orchestrator.source.ComponentId;
import aws.cryptography.esdk.testserver.orchestrator.source.MaterializedSources;
import aws.cryptography.esdk.testserver.orchestrator.source.Materializer;
import aws.cryptography.esdk.testserver.orchestrator.source.ResolvedComponentPlan;
import aws.cryptography.esdk.testserver.orchestrator.source.SourcePlan;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.StringJoiner;

/**
 * A test double {@link Materializer}: turns every plan into a successful
 * outcome with a dummy directory and commit — no git, no filesystem clones — so
 * the orchestrator error-path and pipeline tests run deterministically without
 * cloning repositories (design: keep git behind an abstraction; real
 * materialization is exercised by the real-git integration tests).
 *
 * <p>For every {@code server:<lang>} component it also writes a catalog-complete
 * {@code esdk/test-server/commons-configuration.json} under the resolved server
 * root, so the orchestrator's stage-3 cross-repository Feature validation (a
 * Commons_Run reads a language's Feature_Declaration + {@code product} from the
 * materialized commons-configuration file — design "The orchestrated run
 * pipeline", Requirements 8.4, 8.11) finds a valid declaration. The written
 * declaration lists every catalog Feature as supported with {@code product}
 * matching the run's Configuration_Set, so a language whose stored entry carries
 * no inline declaration validates cleanly and the pipeline proceeds to the
 * launch/report stages under test.
 */
final class FakeMaterializer implements Materializer {

    private final Path root;
    private final String product;
    private final List<String> catalog;

    /** language -> rawRsaPaddingSchemes to write into that server's declaration. */
    private final Map<String, List<String>> rawRsaPaddingSchemes = new LinkedHashMap<>();

    private FakeMaterializer(Path root, String product, List<String> catalog) {
        this.root = root;
        this.product = product;
        this.catalog = catalog;
    }

    /**
     * Also write a {@code rawRsaPaddingSchemes} capability into
     * {@code language}'s materialized commons-configuration file, so pipeline
     * tests can exercise the stage-3 carried-capability path.
     */
    FakeMaterializer withRawRsaPaddingSchemes(String language, List<String> schemes) {
        rawRsaPaddingSchemes.put(language, List.copyOf(schemes));
        return this;
    }

    /**
     * A materializer that succeeds for every plan under {@code root}, writing a
     * catalog-complete commons-configuration file (matching {@code set}'s
     * {@code product} and Feature_Catalog) into each server root so stage-3
     * Feature validation passes.
     */
    static FakeMaterializer succeedingUnder(Path root, ConfigurationSet set) {
        return new FakeMaterializer(root, set.product(),
            set.features() == null ? List.of() : set.features());
    }

    @Override
    public MaterializedSources materialize(List<ResolvedComponentPlan> plans) {
        List<MaterializedSources.Outcome> outcomes = new ArrayList<>(plans.size());
        for (ResolvedComponentPlan plan : plans) {
            boolean workingTree = plan.plan() instanceof SourcePlan.WorkingTree;
            Path componentRoot = root.resolve(plan.component().toString().replace(':', '-'));
            MaterializedSources.Success success = new MaterializedSources.Success(
                plan.component(), plan.plan(), plan.reason(),
                componentRoot,
                "0000000000000000000000000000000000000000",
                "fake-ref",
                workingTree ? Boolean.FALSE : null);
            if (plan.component().kind() == ComponentId.Kind.SERVER) {
                // Write at the location the pipeline's stage-3 read computes —
                // Success.root() (the plan's working-tree root, or the clone
                // root), not the raw component directory.
                writeCommonsConfiguration(success.root(),
                    rawRsaPaddingSchemes.get(plan.component().language()));
            }
            outcomes.add(success);
        }
        return new MaterializedSources(outcomes);
    }

    /**
     * Write a catalog-complete {@code commons-configuration.json} under the
     * server component's resolved root (at the design's
     * {@code esdk/test-server/commons-configuration.json} relative path) so the
     * orchestrator's stage-3 cross-repository Feature validation read succeeds.
     */
    private void writeCommonsConfiguration(Path serverRoot, List<String> paddingSchemes) {
        Path file = serverRoot.resolve(ESDKTestServer.COMMONS_CONFIGURATION_RELATIVE_PATH);
        try {
            Files.createDirectories(file.getParent());
            Files.writeString(file, commonsConfigurationJson(paddingSchemes));
        } catch (IOException e) {
            throw new UncheckedIOException(
                "fake materializer could not write " + file, e);
        }
    }

    private String commonsConfigurationJson(List<String> paddingSchemes) {
        StringJoiner supported = new StringJoiner(", ", "[", "]");
        for (String feature : catalog) {
            supported.add('"' + feature + '"');
        }
        return "{\n"
            + "  \"commonsRepository\": {\n"
            + "    \"name\": \"aws-crypto-tools-commons\",\n"
            + "    \"url\": \"git@github.com:aws/aws-crypto-tools-commons.git\",\n"
            + "    \"branch\": \"main\"\n"
            + "  },\n"
            + "  \"product\": \"" + product + "\",\n"
            + "  \"supportedFeatures\": " + supported + ",\n"
            + "  \"unsupportedFeatures\": []"
            + (paddingSchemes == null ? "" : ",\n  \"rawRsaPaddingSchemes\": "
                + jsonArray(paddingSchemes))
            + "\n}\n";
    }

    private static String jsonArray(List<String> values) {
        StringJoiner joined = new StringJoiner(", ", "[", "]");
        for (String value : values) {
            joined.add('"' + value + '"');
        }
        return joined.toString();
    }
}
