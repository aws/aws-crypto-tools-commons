package aws.cryptography.dbesdk.testserver.tests.wire;

import aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers;
import aws.cryptography.dbesdk.testserver.tests.DbeTestServerClients;

import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.FOOT;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.PK;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.TABLE;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.bytesOf;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.canonicalPlaintext;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.encryptOnce;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.newKmsClient;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.standardActions;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import aws.cryptography.dbesdk.testserver.client.client.DBESDKTestServerClient;
import aws.cryptography.dbesdk.testserver.client.model.AttributeValue;
import aws.cryptography.testserver.tests.LanguageServerTarget;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Footer byte-level structural facts. The {@code aws_dbe_foot} attribute
 * carries the Recipient Tag (HMAC-SHA-384, 48 bytes) and — under a signing
 * algorithm suite — the ECDSA-P384 signature appended after the tag
 * ({@code specification/structured-encryption/footer.md}). The exact
 * signature-length spec conformance (96 bytes) is asserted as a known bug in
 * the footer tests of {@code ItemIntegrityRejectionTests}.
 *
 * <p><b>Topology: target-local.</b> Every assertion is a structural check on
 * an item the encrypting server produces, so each runs once per configured
 * target via {@link DbeTestHelpers#targets()} rather than across the N&sup2;
 * pair matrix.
 *
 * <p><b>Tests here:</b>
 * <ol>
 *   <li>{@link #footerAttributeIsPresent} — every encrypted item has an aws_dbe_foot attribute</li>
 *   <li>{@link #footerIsAtLeast48Bytes} — the Recipient Tag alone is 48 bytes; the footer is that plus signature</li>
 *   <li>{@link #footerBytesDifferBetweenEncrypts} — a fresh ECDSA signature (and fresh derived tag) per encrypt</li>
 * </ol>
 */
class FooterIntegrityFormatTests {

    /** Recipient Tag length — HMAC-SHA-384 is 48 bytes. */
    private static final int RECIPIENT_TAG_LEN = 48;

    static Stream<LanguageServerTarget> targets() {
        return DbeTestHelpers.targets().stream();
    }

    private static Map<String, AttributeValue> encrypt(LanguageServerTarget target) {
        DBESDKTestServerClient client = DbeTestServerClients.forEndpoint(target.endpoint());
        String clientId = newKmsClient(client, TABLE, PK, standardActions(), List.of());
        return encryptOnce(client, clientId, canonicalPlaintext());
    }

    /** Every encrypted item MUST carry an {@code aws_dbe_foot} attribute. */
    @ParameterizedTest(name = "encrypted item contains aws_dbe_foot attribute {0}")
    @MethodSource("targets")
    void footerAttributeIsPresent(LanguageServerTarget target) {
        Map<String, AttributeValue> item = encrypt(target);
        //= specification/structured-encryption/encrypt-path-structure.md#encrypted-structured-data
        //= type=test
        //# - The [Footer Field](#footer-field) MUST exist in the final Encrypted Structured Data
        //
        //= specification/structured-encryption/encrypt-path-structure.md#footer-field
        //= type=test
        //# The Footer Field name MUST be `aws_dbe_foot`
        assertNotNull(item.get(FOOT),
            "encrypted item must carry an aws_dbe_foot attribute (" + target + ")");
    }

    /**
     * The footer is at least 48 bytes (the Recipient Tag alone). Under the
     * default ECDSA-signed suite it is longer — the ECDSA-P384 signature is
     * appended after the tag. The exact signing footer length is asserted (as a
     * known bug) in the footer tests of {@code ItemIntegrityRejectionTests}; this test asserts
     * only the Recipient-Tag lower bound.
     */
    @ParameterizedTest(name = "footer is at least 48 bytes {0}")
    @MethodSource("targets")
    void footerIsAtLeast48Bytes(LanguageServerTarget target) {
        byte[] footer = bytesOf(encrypt(target).get(FOOT));
        //= specification/structured-encryption/footer.md#recipient-tags
        //= type=test
        //= reason=one 48-byte Recipient Tag per Encrypted Data Key sets the footer's 48-byte floor
        //# There MUST be one Recipient Tag for each Encrypted Data Key in the [header](./header.md#encrypted-data-keys)
        assertTrue(footer.length >= RECIPIENT_TAG_LEN,
            "footer must contain at least a 48-byte Recipient Tag; got " + footer.length
                + " bytes (" + target + ")");
    }

    /**
     * Two independent encrypts of identical plaintext MUST produce different
     * footer bytes. Freshness at the signature layer: the ECDSA signature
     * incorporates fresh randomness, and the Recipient Tag depends on the
     * message ID which is fresh per encrypt.
     */
    @ParameterizedTest(name = "footer bytes differ between two encrypts {0}")
    @MethodSource("targets")
    void footerBytesDifferBetweenEncrypts(LanguageServerTarget target) {
        byte[] foot1 = bytesOf(encrypt(target).get(FOOT));
        byte[] foot2 = bytesOf(encrypt(target).get(FOOT));
        assertFalse(Arrays.equals(foot1, foot2),
            "two independent encrypts of identical plaintext must produce different footer bytes ("
                + target + ")");
    }
}
