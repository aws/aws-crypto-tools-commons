package aws.cryptography.esdk.testserver.orchestrator.config;

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
 * Pins {@link FeatureValidation#RAW_RSA_PADDING_SCHEMES} to the
 * {@code PaddingScheme} enum in the single source-of-truth Smithy model
 * ({@code ../model/esdk-test-server.smithy}), so adding or renaming a scheme in
 * the model fails here until the validation catalog follows.
 */
class PaddingSchemeCatalogTest {

    @Test
    @DisplayName("RAW_RSA_PADDING_SCHEMES equals the model's PaddingScheme enum members")
    void catalogMatchesTheSmithyModel() throws IOException {
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

        assertEquals(members, FeatureValidation.RAW_RSA_PADDING_SCHEMES,
            "FeatureValidation.RAW_RSA_PADDING_SCHEMES must mirror the model's"
                + " PaddingScheme enum members, in model order");
    }
}
