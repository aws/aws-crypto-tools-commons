package aws.cryptography.esdk.testserver.orchestrator.config;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

/**
 * Unit tests for {@link FeatureValidation}: the Feature_Declaration rules, the
 * commons-configuration {@code product} exact-match check, and the
 * missing/unparseable carrying-file error. The jqwik coverage (Property 2)
 * lives separately.
 */
class FeatureValidationTest {

    private static final List<String> CATALOG = List.of("streaming", "MPL");

    @Nested
    @DisplayName("rawRsaPaddingSchemes capability")
    class RawRsaPaddingSchemes {

        @Test
        @DisplayName("an absent field (null) is valid: every scheme is supported")
        void absentFieldIsValid() {
            FeatureValidation.Result r = FeatureValidation.validateRawRsaPaddingSchemes(
                "java", null, List.of());
            assertTrue(r.valid());
        }

        @Test
        @DisplayName("a subset of model schemes with raw-rsa supported is valid")
        void modelSubsetIsValid() {
            FeatureValidation.Result r = FeatureValidation.validateRawRsaPaddingSchemes(
                "c", List.of("PKCS1", "OAEP_SHA1_MGF1", "OAEP_SHA256_MGF1"),
                List.of("raw-aes", "raw-rsa"));
            assertTrue(r.valid());
        }

        @Test
        @DisplayName("an unknown scheme name is an error naming language and name")
        void unknownSchemeIsError() {
            FeatureValidation.Result r = FeatureValidation.validateRawRsaPaddingSchemes(
                "c", List.of("PKCS1", "OAEP_SHA3_MGF1"), List.of("raw-rsa"));
            assertFalse(r.valid());
            assertEquals(1, r.errors().size());
            assertTrue(r.errors().get(0).contains("c"));
            assertTrue(r.errors().get(0).contains("\"OAEP_SHA3_MGF1\""));
        }

        @Test
        @DisplayName("an empty list is an error: declare raw-rsa unsupported instead")
        void emptyListIsError() {
            FeatureValidation.Result r = FeatureValidation.validateRawRsaPaddingSchemes(
                "c", List.of(), List.of("raw-rsa"));
            assertFalse(r.valid());
            assertEquals(1, r.errors().size());
            assertTrue(r.errors().get(0).contains("raw-rsa Feature unsupported instead"));
        }

        @Test
        @DisplayName("a duplicated scheme name is an error naming each duplicate")
        void duplicateSchemeIsError() {
            FeatureValidation.Result r = FeatureValidation.validateRawRsaPaddingSchemes(
                "c", List.of("PKCS1", "PKCS1"), List.of("raw-rsa"));
            assertFalse(r.valid());
            assertEquals(1, r.errors().size());
            assertTrue(r.errors().get(0).contains("\"PKCS1\""));
            assertTrue(r.errors().get(0).contains("2 times"));
        }

        @Test
        @DisplayName("the field present without raw-rsa in supportedFeatures is an error")
        void withoutRawRsaSupportedIsError() {
            FeatureValidation.Result r = FeatureValidation.validateRawRsaPaddingSchemes(
                "c", List.of("PKCS1"), List.of("raw-aes"));
            assertFalse(r.valid());
            assertEquals(1, r.errors().size());
            assertTrue(r.errors().get(0).contains("\"raw-rsa\""));
        }
    }

    @Nested
    @DisplayName("catalog coverage (Requirements 8.5, 8.6)")
    class CatalogCoverage {

        @Test
        @DisplayName("every catalog Feature in exactly one array is valid")
        void completeDeclarationIsValid() {
            FeatureValidation.Result r = FeatureValidation.validateDeclaration(
                CATALOG, "java", List.of("streaming"), List.of("MPL"));
            assertTrue(r.valid());
            assertTrue(r.errors().isEmpty());
        }

        @Test
        @DisplayName("all Features supported with an empty unsupported array is valid")
        void allSupportedIsValid() {
            FeatureValidation.Result r = FeatureValidation.validateDeclaration(
                CATALOG, "python", List.of("streaming", "MPL"), List.of());
            assertTrue(r.valid());
        }

        @Test
        @DisplayName("a catalog Feature in neither array is an undeclared error naming language and Feature")
        void undeclaredFeatureIsError() {
            FeatureValidation.Result r = FeatureValidation.validateDeclaration(
                CATALOG, "java", List.of("streaming"), List.of());
            assertFalse(r.valid());
            assertEquals(1, r.errors().size());
            assertTrue(r.errors().get(0).contains("java"));
            assertTrue(r.errors().get(0).contains("\"MPL\""));
            assertFalse(r.errors().get(0).contains("\"streaming\""));
        }

        @Test
        @DisplayName("absent arrays (null) leave every catalog Feature undeclared, each named")
        void absentArraysReportEveryCatalogFeature() {
            FeatureValidation.Result r = FeatureValidation.validateDeclaration(
                CATALOG, "java", null, null);
            assertFalse(r.valid());
            assertEquals(2, r.errors().size());
            assertTrue(r.errors().stream().allMatch(e -> e.contains("java")));
            assertTrue(r.errors().stream().anyMatch(e -> e.contains("\"streaming\"")));
            assertTrue(r.errors().stream().anyMatch(e -> e.contains("\"MPL\"")));
        }

        @Test
        @DisplayName("an empty catalog with empty arrays is valid")
        void emptyCatalogEmptyArraysIsValid() {
            assertTrue(FeatureValidation.validateDeclaration(
                List.of(), "java", List.of(), List.of()).valid());
        }
    }

    @Nested
    @DisplayName("both-arrays conflicts (Requirement 8.7)")
    class Conflicts {

        @Test
        @DisplayName("a Feature in both arrays is a conflict error naming language and Feature")
        void featureInBothArraysIsConflict() {
            FeatureValidation.Result r = FeatureValidation.validateDeclaration(
                CATALOG, "python", List.of("streaming", "MPL"), List.of("MPL"));
            assertFalse(r.valid());
            assertEquals(1, r.errors().size());
            assertTrue(r.errors().get(0).contains("python"));
            assertTrue(r.errors().get(0).contains("\"MPL\""));
            assertTrue(r.errors().get(0).contains("both"));
        }

        @Test
        @DisplayName("each conflicting Feature is named")
        void everyConflictingFeatureIsNamed() {
            FeatureValidation.Result r = FeatureValidation.validateDeclaration(
                CATALOG, "java",
                List.of("streaming", "MPL"), List.of("streaming", "MPL"));
            assertFalse(r.valid());
            assertEquals(2, r.errors().size());
            assertTrue(r.errors().stream().anyMatch(e -> e.contains("\"streaming\"")));
            assertTrue(r.errors().stream().anyMatch(e -> e.contains("\"MPL\"")));
        }
    }

    @Nested
    @DisplayName("unknown Features (Requirement 8.8)")
    class UnknownFeatures {

        @Test
        @DisplayName("an unknown Feature in supportedFeatures is an error naming language and Feature")
        void unknownInSupported() {
            FeatureValidation.Result r = FeatureValidation.validateDeclaration(
                CATALOG, "java",
                List.of("streaming", "MPL", "compression"), List.of());
            assertFalse(r.valid());
            assertEquals(1, r.errors().size());
            assertTrue(r.errors().get(0).contains("java"));
            assertTrue(r.errors().get(0).contains("\"compression\""));
            assertTrue(r.errors().get(0).contains("supportedFeatures"));
        }

        @Test
        @DisplayName("an unknown Feature in unsupportedFeatures is an error naming the array")
        void unknownInUnsupported() {
            FeatureValidation.Result r = FeatureValidation.validateDeclaration(
                CATALOG, "python",
                List.of("streaming", "MPL"), List.of("caching"));
            assertFalse(r.valid());
            assertEquals(1, r.errors().size());
            assertTrue(r.errors().get(0).contains("\"caching\""));
            assertTrue(r.errors().get(0).contains("unsupportedFeatures"));
        }

        @Test
        @DisplayName("Feature names are compared by exact string comparison (case matters)")
        void exactStringComparison() {
            FeatureValidation.Result r = FeatureValidation.validateDeclaration(
                CATALOG, "java", List.of("Streaming", "MPL"), List.of());
            assertFalse(r.valid());
            // "Streaming" is unknown AND "streaming" is undeclared.
            assertTrue(r.errors().stream().anyMatch(
                e -> e.contains("\"Streaming\"") && e.contains("unknown")));
            assertTrue(r.errors().stream().anyMatch(
                e -> e.contains("\"streaming\"") && e.contains("undeclared")));
        }
    }

    @Nested
    @DisplayName("in-array duplicates (Requirement 8.9)")
    class Duplicates {

        @Test
        @DisplayName("a Feature repeated in supportedFeatures is a duplicate error")
        void duplicateInSupported() {
            FeatureValidation.Result r = FeatureValidation.validateDeclaration(
                CATALOG, "java",
                List.of("streaming", "streaming", "MPL"), List.of());
            assertFalse(r.valid());
            assertEquals(1, r.errors().size());
            assertTrue(r.errors().get(0).contains("java"));
            assertTrue(r.errors().get(0).contains("\"streaming\""));
            assertTrue(r.errors().get(0).contains("supportedFeatures"));
        }

        @Test
        @DisplayName("duplicates are reported per array, naming each duplicated name")
        void duplicatesReportedPerArray() {
            FeatureValidation.Result r = FeatureValidation.validateDeclaration(
                CATALOG, "python",
                List.of("streaming", "streaming"), List.of("MPL", "MPL", "MPL"));
            assertFalse(r.valid());
            assertEquals(2, r.errors().size());
            assertTrue(r.errors().stream().anyMatch(
                e -> e.contains("\"streaming\"") && e.contains("supportedFeatures")));
            assertTrue(r.errors().stream().anyMatch(
                e -> e.contains("\"MPL\"") && e.contains("unsupportedFeatures")));
        }

        @Test
        @DisplayName("a duplicated unknown Feature is reported as both duplicate and unknown")
        void duplicatedUnknownFeature() {
            FeatureValidation.Result r = FeatureValidation.validateDeclaration(
                CATALOG, "java",
                List.of("streaming", "MPL", "zip", "zip"), List.of());
            assertFalse(r.valid());
            assertTrue(r.errors().stream().anyMatch(
                e -> e.contains("\"zip\"") && e.contains("2 times")));
            assertTrue(r.errors().stream().anyMatch(
                e -> e.contains("\"zip\"") && e.contains("unknown")));
        }
    }

    @Nested
    @DisplayName("product exact-match check (Requirement 8.11)")
    class ProductMatch {

        @Test
        @DisplayName("an exactly matching product is valid")
        void matchingProductIsValid() {
            assertTrue(FeatureValidation.validateProductMatch(
                "aws-crypto-tools-java", "esdk", "esdk").valid());
        }

        @Test
        @DisplayName("a mismatched product names the Language_Repository and both values")
        void mismatchedProductNamesBothValues() {
            FeatureValidation.Result r = FeatureValidation.validateProductMatch(
                "aws-crypto-tools-java", "dbesdk", "esdk");
            assertFalse(r.valid());
            assertEquals(1, r.errors().size());
            assertTrue(r.errors().get(0).contains("aws-crypto-tools-java"));
            assertTrue(r.errors().get(0).contains("\"dbesdk\""));
            assertTrue(r.errors().get(0).contains("\"esdk\""));
        }

        @Test
        @DisplayName("a missing product names the Language_Repository and the Configuration_Set value")
        void missingProductIsError() {
            FeatureValidation.Result r = FeatureValidation.validateProductMatch(
                "aws-crypto-tools-java", null, "esdk");
            assertFalse(r.valid());
            assertEquals(1, r.errors().size());
            assertTrue(r.errors().get(0).contains("aws-crypto-tools-java"));
            assertTrue(r.errors().get(0).contains("missing"));
            assertTrue(r.errors().get(0).contains("\"esdk\""));
        }

        @Test
        @DisplayName("product comparison is exact string comparison (case matters)")
        void productComparisonIsExact() {
            assertFalse(FeatureValidation.validateProductMatch(
                "aws-crypto-tools-java", "ESDK", "esdk").valid());
        }
    }

    @Nested
    @DisplayName("missing/unparseable carrying file (Requirement 8.10)")
    class CarryingFile {

        @Test
        @DisplayName("the error names the language and the expected location")
        void namesLanguageAndLocation() {
            FeatureValidation.Result r = FeatureValidation.carryingFileError(
                "java", "aws-crypto-tools-java/esdk/test-server/commons-configuration.json",
                "file not found");
            assertFalse(r.valid());
            assertEquals(1, r.errors().size());
            assertTrue(r.errors().get(0).contains("java"));
            assertTrue(r.errors().get(0).contains(
                "aws-crypto-tools-java/esdk/test-server/commons-configuration.json"));
            assertTrue(r.errors().get(0).contains("file not found"));
        }

        @Test
        @DisplayName("a null cause is omitted from the message")
        void nullCauseOmitted() {
            FeatureValidation.Result r = FeatureValidation.carryingFileError(
                "python", "config/configuration-set.json", null);
            assertFalse(r.valid());
            assertTrue(r.errors().get(0).contains("python"));
            assertTrue(r.errors().get(0).contains("config/configuration-set.json"));
        }
    }

    @Nested
    @DisplayName("Result combination")
    class ResultCombination {

        @Test
        @DisplayName("and() of two valid results is valid")
        void andOfValidIsValid() {
            assertTrue(FeatureValidation.Result.ok()
                .and(FeatureValidation.Result.ok()).valid());
        }

        @Test
        @DisplayName("and() concatenates errors in order and is invalid if either is")
        void andConcatenatesErrors() {
            FeatureValidation.Result declaration = FeatureValidation.validateDeclaration(
                CATALOG, "java", List.of("streaming"), List.of());
            FeatureValidation.Result product = FeatureValidation.validateProductMatch(
                "aws-crypto-tools-java", "other", "esdk");
            FeatureValidation.Result combined = declaration.and(product);
            assertFalse(combined.valid());
            assertEquals(2, combined.errors().size());
            assertEquals(declaration.errors().get(0), combined.errors().get(0));
            assertEquals(product.errors().get(0), combined.errors().get(1));
        }
    }
}
