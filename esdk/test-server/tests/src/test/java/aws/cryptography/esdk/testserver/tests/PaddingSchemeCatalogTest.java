package aws.cryptography.esdk.testserver.tests;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Pins the {@code PaddingScheme} enum in the single source-of-truth Smithy model
 * ({@code ../model/esdk-test-server.smithy}) to the raw-RSA padding scheme names
 * the framework recognizes, so adding or renaming a scheme in the model fails
 * here until the framework's padding catalog follows.
 *
 * <p>The framework's catalog is
 * {@code aws.cryptography.testserver.orchestrator.config.FeatureValidation.RAW_RSA_PADDING_SCHEMES}
 * in the shared, product-neutral orchestrator, which the Tests module does not
 * depend on; {@link #EXPECTED_PADDING_SCHEMES} mirrors it and MUST stay equal to
 * it. The shared orchestrator validates each server's {@code rawRsaPaddingSchemes}
 * config against that list, so a name added to the model but not to the catalog
 * would be rejected there — this test catches the drift at its source, in model
 * order.
 */
class PaddingSchemeCatalogTest {

    /**
     * The raw-RSA padding scheme names the shared orchestrator's
     * {@code FeatureValidation.RAW_RSA_PADDING_SCHEMES} defines, in model order.
     * Keep equal to that list.
     */
    private static final List<String> EXPECTED_PADDING_SCHEMES = List.of(
        "PKCS1",
        "OAEP_SHA1_MGF1",
        "OAEP_SHA256_MGF1",
        "OAEP_SHA384_MGF1",
        "OAEP_SHA512_MGF1");

    @Test
    @DisplayName("model PaddingScheme enum members equal the framework's padding catalog")
    void modelMatchesTheCatalog() throws IOException {
        Path model = Path.of("..", "model", "esdk-test-server.smithy")
            .toAbsolutePath().normalize();
        assertTrue(Files.isRegularFile(model), "expected the Smithy model at " + model);

        String smithy = Files.readString(model);
        Matcher block = Pattern.compile("enum\\s+PaddingScheme\\s*\\{([^}]*)}").matcher(smithy);
        assertTrue(block.find(), "expected an 'enum PaddingScheme' block in " + model);

        List<String> members = new ArrayList<>();
        Matcher member = Pattern.compile("^\\s*([A-Z][A-Z0-9_]*)\\s*$", Pattern.MULTILINE)
            .matcher(block.group(1));
        while (member.find()) {
            members.add(member.group(1));
        }

        assertEquals(EXPECTED_PADDING_SCHEMES, members,
            "the model's PaddingScheme enum members must equal the framework's"
                + " raw-RSA padding catalog (FeatureValidation.RAW_RSA_PADDING_SCHEMES),"
                + " in model order");
    }
}
