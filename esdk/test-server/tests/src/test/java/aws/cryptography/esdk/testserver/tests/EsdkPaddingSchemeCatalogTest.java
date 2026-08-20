package aws.cryptography.esdk.testserver.tests;

import static org.junit.jupiter.api.Assertions.assertEquals;

import aws.cryptography.esdk.testserver.client.model.PaddingScheme;
import aws.cryptography.testserver.orchestrator.config.FeatureValidation;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Pins the shared {@link FeatureValidation#RAW_RSA_PADDING_SCHEMES} against
 * the ESDK Smithy model's {@code PaddingScheme} enum (as exposed by the
 * generated {@link PaddingScheme} client type). Adding or renaming a scheme
 * in the ESDK model fails here until the shared validation catalog follows.
 *
 * <p>The shared catalog is a {@code List<String>} carrying every scheme every
 * SDK supports; this test asserts it contains, in the same order, every value
 * of the ESDK-modeled enum. A per-SDK counterpart in each other SDK's Tests
 * module pins the same list against its own enum.
 */
class EsdkPaddingSchemeCatalogTest {

    @Test
    @DisplayName("RAW_RSA_PADDING_SCHEMES matches the ESDK model's PaddingScheme enum members in order")
    void catalogMatchesTheEsdkSmithyEnum() {
        List<String> modeled = PaddingScheme.values().stream()
            .map(PaddingScheme::getValue)
            .toList();

        assertEquals(modeled, FeatureValidation.RAW_RSA_PADDING_SCHEMES,
            "FeatureValidation.RAW_RSA_PADDING_SCHEMES must mirror the ESDK model's"
                + " PaddingScheme enum members in enum order — update the shared catalog"
                + " when the ESDK model gains, renames, or removes a scheme");
    }
}
