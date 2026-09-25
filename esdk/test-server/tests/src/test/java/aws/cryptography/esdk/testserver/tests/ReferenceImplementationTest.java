package aws.cryptography.esdk.testserver.tests;

import aws.cryptography.testserver.tests.FeatureDeclarations;
import aws.cryptography.testserver.tests.LanguageServerRegistry;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import aws.cryptography.esdk.testserver.client.model.PaddingScheme;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Unit tests for {@link ReferenceImplementation}'s reference selection,
 * capability substitution, and property parsing — all against explicit
 * registries via the package-private seams, so nothing touches the JVM-wide
 * singletons or system properties.
 */
class ReferenceImplementationTest {

    private static final LanguageServerRegistry REGISTRY = LanguageServerRegistry.parse(
        "java:3:aws-crypto-tools-java=http://127.0.0.1:1,"
            + "python:4:aws-encryption-sdk-python=http://127.0.0.1:2,"
            + "c:2:aws-encryption-sdk-c=http://127.0.0.1:3");

    private static final String CATALOG = "raw-aes,raw-rsa";

    private static FeatureDeclarations declarations(String features, String paddings) {
        return FeatureDeclarations.parse(features, CATALOG, paddings);
    }

    @Test
    @DisplayName("the reference language defaults to java and takes the configured value trimmed")
    void referenceLanguageDefaultsAndParses() {
        assertEquals("java", ReferenceImplementation.referenceLanguage(null));
        assertEquals("java", ReferenceImplementation.referenceLanguage("  "));
        assertEquals("python", ReferenceImplementation.referenceLanguage(" python "));
    }

    @Test
    @DisplayName("decrypt-side rows: one per target in configuration order, the reference producing every message")
    void composesOneRowPerTargetWithTheReferenceProducing() {
        FeatureDeclarations declarations = declarations(
            "java:3:aws-crypto-tools-java:raw-aes=true;raw-rsa=false,python:4:aws-encryption-sdk-python:raw-aes=true;raw-rsa=true,"
                + "c:2:aws-encryption-sdk-c:raw-aes=true;raw-rsa=true", null);

        List<ReferencePair> rows = ReferenceImplementation.decryptSide(
            Set.of("raw-aes"), Set.of(), REGISTRY, declarations, "java");

        assertEquals(3, rows.size(), "one row per configured target");
        assertEquals(List.of("java-v3", "python-v4", "c-v2"),
            rows.stream().map(r -> r.decryptTarget().label()).toList(),
            "decryptors in configuration order");
        assertTrue(rows.stream().allMatch(r -> r.encryptTarget().label().equals("java-v3")),
            "the reference produces every row's message");
        assertTrue(rows.stream().noneMatch(ReferencePair::substituted));
        assertEquals("ref:java-v3->python-v4", rows.get(1).toString());
    }

    @Test
    @DisplayName("a reference lacking a required Feature is substituted by the first capable target in configuration order")
    void substitutesOnMissingFeature() {
        FeatureDeclarations declarations = declarations(
            "java:3:aws-crypto-tools-java:raw-aes=true;raw-rsa=false,python:4:aws-encryption-sdk-python:raw-aes=true;raw-rsa=true,"
                + "c:2:aws-encryption-sdk-c:raw-aes=true;raw-rsa=true", null);

        List<ReferencePair> rows = ReferenceImplementation.decryptSide(
            Set.of("raw-rsa"), Set.of(), REGISTRY, declarations, "java");

        assertTrue(rows.stream().allMatch(r -> r.encryptTarget().label().equals("python-v4")),
            "python is the first raw-rsa-capable target in configuration order");
        assertTrue(rows.stream().allMatch(ReferencePair::substituted));
        assertEquals("ref(sub):python-v4->java-v3", rows.get(0).toString(),
            "substituted rows are annotated in the display name");
    }

    @Test
    @DisplayName("a reference lacking a required raw-RSA padding is substituted")
    void substitutesOnMissingPadding() {
        FeatureDeclarations declarations = declarations(
            "java:3:aws-crypto-tools-java:raw-aes=true;raw-rsa=true,python:4:aws-encryption-sdk-python:raw-aes=true;raw-rsa=true,"
                + "c:2:aws-encryption-sdk-c:raw-aes=true;raw-rsa=true",
            "java:3:aws-crypto-tools-java:PKCS1");

        List<ReferencePair> rows = ReferenceImplementation.decryptSide(
            Set.of("raw-rsa"), Set.of(PaddingScheme.OAEP_SHA256_MGF1),
            REGISTRY, declarations, "java");

        assertTrue(rows.stream().allMatch(r -> r.encryptTarget().label().equals("python-v4")),
            "java declares only PKCS1, so python substitutes");
        assertTrue(rows.stream().allMatch(ReferencePair::substituted));
    }

    @Test
    @DisplayName("a reference language with no configured target is substituted (single-language runs)")
    void substitutesWhenReferenceHasNoTarget() {
        LanguageServerRegistry cOnly = LanguageServerRegistry.parse("c:2:aws-encryption-sdk-c=http://127.0.0.1:3");
        FeatureDeclarations declarations = declarations("c:2:aws-encryption-sdk-c:raw-aes=true;raw-rsa=true", null);

        List<ReferencePair> rows = ReferenceImplementation.decryptSide(
            Set.of("raw-aes"), Set.of(), cOnly, declarations, "java");

        assertEquals(1, rows.size());
        assertEquals("ref(sub):c-v2->c-v2", rows.get(0).toString());
    }

    @Test
    @DisplayName("with no capable language the rows are still composed so every decryptor feature-gates visibly")
    void composesRowsWhenNothingIsCapable() {
        FeatureDeclarations declarations = declarations(
            "java:3:aws-crypto-tools-java:raw-aes=true;raw-rsa=false,python:4:aws-encryption-sdk-python:raw-aes=true;raw-rsa=false,"
                + "c:2:aws-encryption-sdk-c:raw-aes=true;raw-rsa=false", null);

        List<ReferencePair> rows = ReferenceImplementation.decryptSide(
            Set.of("raw-rsa"), Set.of(), REGISTRY, declarations, "java");

        assertEquals(3, rows.size(), "no row vanishes from the case list");
        assertTrue(rows.stream().allMatch(r -> r.encryptTarget().label().equals("java-v3")),
            "the reference's own target anchors the visibly-gated rows");
        assertFalse(rows.get(0).substituted());
    }

    @Test
    @DisplayName("the reference language's first configured target is picked when it ships multiple majors")
    void picksTheFirstTargetOfTheReferenceLanguage() {
        LanguageServerRegistry twoMajors = LanguageServerRegistry.parse(
            "java:3:aws-crypto-tools-java=http://127.0.0.1:1,"
                + "java:4:aws-crypto-tools-java=http://127.0.0.1:2,"
                + "python:4:aws-encryption-sdk-python=http://127.0.0.1:3");
        FeatureDeclarations declarations = declarations(
            "java:3:aws-crypto-tools-java:raw-aes=true;raw-rsa=true,python:4:aws-encryption-sdk-python:raw-aes=true;raw-rsa=true", null);

        List<ReferencePair> rows = ReferenceImplementation.decryptSide(
            Set.of("raw-aes"), Set.of(), twoMajors, declarations, "java");

        assertTrue(rows.stream().allMatch(r -> r.encryptTarget().label().equals("java-v3")));
    }
}
