package aws.cryptography.dbesdk.testserver.tests.configuration;

import aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers;
import aws.cryptography.dbesdk.testserver.tests.DbeTestServerClients;

import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.HEAD;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.PK;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.PUBLIC;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.SECRET;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.TABLE;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.bytesOf;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.canonicalPlaintext;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.encryptLegendBytes;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.encryptOnce;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.newKmsClient;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.standardActions;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.v1StandardActions;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import aws.cryptography.dbesdk.testserver.client.client.DBESDKTestServerClient;
import aws.cryptography.dbesdk.testserver.client.model.AttributeValue;
import aws.cryptography.dbesdk.testserver.client.model.CryptoAction;
import aws.cryptography.dbesdk.testserver.client.model.DBESDKTestServerException;
import aws.cryptography.testserver.tests.LanguageServerTarget;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Configuration-Version WIRE ENCODING — the producer-side, single-server facts a
 * v1 vs v2 schema stamps onto the header: the format-version byte and the Encrypt
 * Legend action bytes. The Configuration Version is chosen by the presence
 * ({@code v2}) or absence ({@code v1}) of {@code SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT}
 * in the schema ({@code ddb-table-encryption-config.md#configuration-version}).
 *
 * <p><b>Topology: target-local.</b> Only the encrypting server produces these
 * bytes, so each assertion runs once per configured target (via
 * {@link DbeTestHelpers#targets()}), not across the N&sup2; pair matrix.
 * Cross-runtime read behavior lives in
 * {@link ConfigurationVersionReadCompatibilityTests}.
 *
 * <p>V1: no {@code SIGN_AND_INCLUDE}, version byte {@code 0x01}, legend {@code s/s/e}.
 * <br>V2: at least one {@code SIGN_AND_INCLUDE}, version byte {@code 0x02}, legend {@code c/c/e}.
 */
class ConfigurationVersionWireEncodingTests {

    private static final byte VERSION_V1 = 0x01;
    private static final byte VERSION_V2 = 0x02;
    private static final byte LEGEND_ENCRYPT_AND_SIGN = 0x65; // 'e'
    private static final byte LEGEND_SIGN_ONLY = 0x73;        // 's'
    private static final byte LEGEND_SIGN_AND_INCLUDE = 0x63; // 'c'

    /** Reserved attribute-name prefix — cannot appear in any user-configured schema. */
    private static final String RESERVED_PREFIX_NAME = "aws_dbe_reserved";

    // One v1 item and one v2 item per target, memoized so the version-byte and
    // legend assertions share a single encrypt per (target, version).
    private static final Map<LanguageServerTarget, Map<String, AttributeValue>> V1_ITEMS =
        new ConcurrentHashMap<>();
    private static final Map<LanguageServerTarget, Map<String, AttributeValue>> V2_ITEMS =
        new ConcurrentHashMap<>();

    static Stream<LanguageServerTarget> targets() {
        return DbeTestHelpers.targets().stream();
    }

    private static Map<String, AttributeValue> v1Item(LanguageServerTarget target) {
        return V1_ITEMS.computeIfAbsent(target, t -> encryptWith(t, v1StandardActions()));
    }

    private static Map<String, AttributeValue> v2Item(LanguageServerTarget target) {
        return V2_ITEMS.computeIfAbsent(target, t -> encryptWith(t, standardActions()));
    }

    private static Map<String, AttributeValue> encryptWith(
            LanguageServerTarget target, Map<String, CryptoAction> actions) {
        DBESDKTestServerClient client = DbeTestServerClients.forEndpoint(target.endpoint());
        String clientId = newKmsClient(client, TABLE, PK, actions, List.of());
        return encryptOnce(client, clientId, canonicalPlaintext());
    }

    /** A schema with no SIGN_AND_INCLUDE is v1 → header version byte 0x01. */
    @ParameterizedTest(name = "v1 config -> version byte 0x01 {0}")
    @MethodSource("targets")
    void v1ConfigProducesVersionByte01(LanguageServerTarget target) {
        byte[] header = bytesOf(v1Item(target).get(HEAD));
        //= specification/dynamodb-encryption-client/ddb-table-encryption-config.md#configuration-version
        //= type=test
        //# If any of the [Attribute Actions](#attribute-actions) are configured as
        //# [SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT](../structured-encryption/structures.md#contextandsign)
        //# then the configuration version MUST be 2; otherwise,
        //# the configuration version MUST be 1.
        assertEquals(VERSION_V1, header[0],
            "a schema without SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT must produce a header whose "
                + "version byte is 0x01 (" + target + ")");
    }

    /** V1 legend: SIGN_ONLY -> 's' (0x73), ENCRYPT_AND_SIGN -> 'e' (0x65); schema (PK, public, secret) -> "sse". */
    @ParameterizedTest(name = "v1 encrypt legend encodes actions as s/s/e {0}")
    @MethodSource("targets")
    void v1EncryptLegendEncodesActionsAsExpected(LanguageServerTarget target) {
        byte[] legend = encryptLegendBytes(v1Item(target));
        //= specification/structured-encryption/header.md#encrypt-legend-bytes
        //= type=test
        //# - `0x65` (`e` in UTF-8, for "Encrypt and Sign") means that a particular field was encrypted
        //= specification/structured-encryption/header.md#encrypt-legend-bytes
        //= type=test
        //# - `0x73` (`s` in UTF-8, for "Sign Only") means that a particular field was not encrypted,
        assertEquals(3, legend.length,
            "v1 encrypt legend must have one byte per authenticated attribute (schema has 3): " + target);
        assertEquals(LEGEND_SIGN_ONLY, legend[0],
            "v1 legend[0] must be 0x73 ('s') for PK=SIGN_ONLY (" + target + ")");
        assertEquals(LEGEND_SIGN_ONLY, legend[1],
            "v1 legend[1] must be 0x73 ('s') for public=SIGN_ONLY (" + target + ")");
        assertEquals(LEGEND_ENCRYPT_AND_SIGN, legend[2],
            "v1 legend[2] must be 0x65 ('e') for secret=ENCRYPT_AND_SIGN (" + target + ")");
    }

    /** A v2 schema produces a header with version byte 0x02. */
    @ParameterizedTest(name = "v2 config -> version byte 0x02 {0}")
    @MethodSource("targets")
    void v2ConfigProducesVersionByte02(LanguageServerTarget target) {
        byte[] header = bytesOf(v2Item(target).get(HEAD));
        //= specification/dynamodb-encryption-client/ddb-table-encryption-config.md#configuration-version
        //= type=test
        //# If any of the [Attribute Actions](#attribute-actions) are configured as
        //# [SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT](../structured-encryption/structures.md#contextandsign)
        //# then the configuration version MUST be 2; otherwise,
        //# the configuration version MUST be 1.
        assertEquals(VERSION_V2, header[0],
            "a v2 schema must produce a header whose version byte is 0x02 (" + target + ")");
    }

    /** V2 legend: SIGN_AND_INCLUDE -> 'c' (0x63), ENCRYPT_AND_SIGN -> 'e' (0x65); schema -> "cce". */
    @ParameterizedTest(name = "v2 encrypt legend encodes actions as c/c/e {0}")
    @MethodSource("targets")
    void v2EncryptLegendEncodesActionsAsExpected(LanguageServerTarget target) {
        byte[] legend = encryptLegendBytes(v2Item(target));
        //= specification/structured-encryption/header.md#encrypt-legend-bytes
        //= type=test
        //# - `0x65` (`e` in UTF-8, for "Encrypt and Sign") means that a particular field was encrypted
        //= specification/structured-encryption/header.md#encrypt-legend-bytes
        //= type=test
        //# - `0x63` (`c` in UTF-8, for "Context") means that a particular field was not encrypted,
        assertEquals(3, legend.length,
            "v2 encrypt legend must have one byte per authenticated attribute (schema has 3): " + target);
        assertEquals(LEGEND_SIGN_AND_INCLUDE, legend[0],
            "v2 legend[0] must be 0x63 ('c') for PK=SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT (" + target + ")");
        assertEquals(LEGEND_SIGN_AND_INCLUDE, legend[1],
            "v2 legend[1] must be 0x63 ('c') for public=SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT (" + target + ")");
        assertEquals(LEGEND_ENCRYPT_AND_SIGN, legend[2],
            "v2 legend[2] must be 0x65 ('e') for secret=ENCRYPT_AND_SIGN (" + target + ")");
    }

    /**
     * Attribute names beginning with the {@code aws_dbe_} reserved prefix MUST be
     * rejected at CreateClient (the library owns that prefix for {@code aws_dbe_head}
     * / {@code aws_dbe_foot}). Target-local: CreateClient validation is a single-server
     * behavior. The rule is version-independent, so one Configuration Version suffices.
     */
    @ParameterizedTest(name = "CreateClient rejects reserved-prefix attribute name {0}")
    @MethodSource("targets")
    void rejectsReservedPrefixAttributeName(LanguageServerTarget target) {
        DBESDKTestServerClient client = DbeTestServerClients.forEndpoint(target.endpoint());
        Map<String, CryptoAction> reservedActions = new LinkedHashMap<>();
        reservedActions.put(PK, CryptoAction.SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT);
        reservedActions.put(SECRET, CryptoAction.ENCRYPT_AND_SIGN);
        reservedActions.put(PUBLIC, CryptoAction.SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT);
        reservedActions.put(RESERVED_PREFIX_NAME, CryptoAction.SIGN_ONLY);
        assertThrows(DBESDKTestServerException.class,
            () -> newKmsClient(client, TABLE, PK, reservedActions, List.of()),
            "CreateClient must reject a schema whose attribute name starts with the reserved "
                + "'aws_dbe_' prefix (" + target + ")");
    }

    // =========================================================================
    // Encrypt Legend ORDERING — the legend serializes one byte per AUTHENTICATED
    // attribute, ordered by [Canonical Path]. The Canonical Path compares the
    // 8-byte length prefix FIRST, then the UTF-8 name bytes (length-first, then
    // lexicographic), INDEPENDENT of the item/schema input order. DO_NOTHING
    // attributes are unauthenticated and produce NO byte. These mirror the Dafny
    // StructuredEncryption Header tests TestSchemaOrderAlpha / TestSchemaOrderLength
    // / TestSchemaOrderLength2 at the DDB item-encryptor layer. All three use a v1
    // schema (SIGN_ONLY / ENCRYPT_AND_SIGN / DO_NOTHING, no SIGN_AND_INCLUDE), so
    // the legend uses only 's' and 'e'; DO_NOTHING names are ":"-prefixed to
    // satisfy the allowed-unsigned prefix rule. The partition key PK (SIGN_ONLY,
    // length 2) is itself authenticated and, being the shortest name, sorts first.
    // =========================================================================

    /**
     * Equal-length authenticated names supplied in scrambled input order must
     * appear in the legend in alphabetical order, with DO_NOTHING attributes
     * excluded. Length-3 names {@code abc}/{@code def}/{@code jkl}/{@code mno}
     * (E/S/E/S) plus two DO_NOTHING attributes, inserted out of order; PK
     * (SIGN_ONLY, length 2) sorts first by the length-first rule. Canonical
     * order → PK, abc, def, jkl, mno → legend {@code s,e,s,e,s}. Mirrors the
     * Dafny {@code TestSchemaOrderAlpha}.
     */
    @ParameterizedTest(name = "encrypt legend orders equal-length names alphabetically {0}")
    @MethodSource("targets")
    void encryptLegendOrdersEqualLengthNamesAlphabetically(LanguageServerTarget target) {
        Map<String, CryptoAction> actions = new LinkedHashMap<>();
        actions.put(PK, CryptoAction.SIGN_ONLY);
        actions.put("mno", CryptoAction.SIGN_ONLY);
        actions.put(":pqr", CryptoAction.DO_NOTHING);
        actions.put("abc", CryptoAction.ENCRYPT_AND_SIGN);
        actions.put("jkl", CryptoAction.ENCRYPT_AND_SIGN);
        actions.put(":ghi", CryptoAction.DO_NOTHING);
        actions.put("def", CryptoAction.SIGN_ONLY);

        byte[] legend = encryptLegend(target, actions, List.of(":ghi", ":pqr"));

        // Authenticated attributes in Canonical Path order (length-first, then
        // lexicographic): PK (len 2)=SIGN_ONLY, then the length-3 names in
        // alphabetical order — abc=ENCRYPT_AND_SIGN, def=SIGN_ONLY,
        // jkl=ENCRYPT_AND_SIGN, mno=SIGN_ONLY. The DO_NOTHING attributes
        // (:ghi, :pqr) contribute no legend byte.
        byte[] expected = {
            LEGEND_SIGN_ONLY,        // PK
            LEGEND_ENCRYPT_AND_SIGN, // abc
            LEGEND_SIGN_ONLY,        // def
            LEGEND_ENCRYPT_AND_SIGN, // jkl
            LEGEND_SIGN_ONLY,        // mno
        };
        //= specification/structured-encryption/header.md#encrypt-legend-bytes
        //= type=test
        //# The Encrypt Legend Bytes MUST be serialized as follows:
        //#
        //# 1. Order every authenticated attribute in the item by the [Canonical Path](#canonical-path)
        assertArrayEquals(expected, legend,
            "equal-length authenticated names must appear in the legend in alphabetical order "
                + "(DO_NOTHING excluded), independent of schema input order (" + target + ")");
    }

    /**
     * Names whose length-first order differs from pure alphabetical order:
     * {@code aa}/{@code zz}/{@code aaa}/{@code zzz}/{@code aaaa}/{@code zzzz}.
     * The Canonical Path compares the 8-byte length prefix first, so shorter
     * names precede longer ones regardless of alphabet. Canonical order →
     * PK, aa, zz, zzz, aaaa → legend {@code s,e,s,e,s}. A pure-alphabetical
     * ordering would instead be PK, aa, aaaa, zz, zzz → {@code s,e,s,s,e}, a
     * different sequence, so this discriminates length-first specifically.
     * Mirrors the Dafny {@code TestSchemaOrderLength}.
     */
    @ParameterizedTest(name = "encrypt legend orders by Canonical Path length-first {0}")
    @MethodSource("targets")
    void encryptLegendOrdersByCanonicalPathLengthFirst(LanguageServerTarget target) {
        Map<String, CryptoAction> actions = new LinkedHashMap<>();
        actions.put(PK, CryptoAction.SIGN_ONLY);
        actions.put("zz", CryptoAction.SIGN_ONLY);
        actions.put("aa", CryptoAction.ENCRYPT_AND_SIGN);
        actions.put(":zzzz", CryptoAction.DO_NOTHING);
        actions.put("aaaa", CryptoAction.SIGN_ONLY);
        actions.put("zzz", CryptoAction.ENCRYPT_AND_SIGN);
        actions.put(":aaa", CryptoAction.DO_NOTHING);

        byte[] legend = encryptLegend(target, actions, List.of(":aaa", ":zzzz"));

        // Authenticated attributes in Canonical Path order (length-first, then
        // lexicographic): len-2 group {PK, aa, zz} ordered PK (0x50) < aa (0x61)
        // < zz (0x7A), then len-3 zzz, then len-4 aaaa:
        //   PK=SIGN_ONLY, aa=ENCRYPT_AND_SIGN, zz=SIGN_ONLY, zzz=ENCRYPT_AND_SIGN,
        //   aaaa=SIGN_ONLY. The DO_NOTHING attributes (:aaa, :zzzz) contribute no byte.
        byte[] expected = {
            LEGEND_SIGN_ONLY,        // PK   (len 2)
            LEGEND_ENCRYPT_AND_SIGN, // aa   (len 2)
            LEGEND_SIGN_ONLY,        // zz   (len 2)
            LEGEND_ENCRYPT_AND_SIGN, // zzz  (len 3)
            LEGEND_SIGN_ONLY,        // aaaa (len 4)
        };
        //= specification/structured-encryption/header.md#encrypt-legend-bytes
        //= type=test
        //# The Encrypt Legend Bytes MUST be serialized as follows:
        //#
        //# 1. Order every authenticated attribute in the item by the [Canonical Path](#canonical-path)
        assertArrayEquals(expected, legend,
            "authenticated attributes must be ordered length-first by Canonical Path (then "
                + "lexicographically), not by pure alphabetical name (" + target + ")");
    }

    /**
     * The legend order is a property of the Canonical Path, not of the input
     * order. Same name→action mapping as
     * {@link #encryptLegendOrdersByCanonicalPathLengthFirst} supplied in a
     * different input permutation must yield the SAME legend bytes
     * ({@code s,e,s,e,s}). Mirrors the Dafny {@code TestSchemaOrderLength2}.
     */
    @ParameterizedTest(name = "encrypt legend order is independent of input order {0}")
    @MethodSource("targets")
    void encryptLegendOrderIndependentOfInputOrder(LanguageServerTarget target) {
        // Identical name->action mapping to the length-first test, permuted.
        Map<String, CryptoAction> actions = new LinkedHashMap<>();
        actions.put(PK, CryptoAction.SIGN_ONLY);
        actions.put("aaaa", CryptoAction.SIGN_ONLY);
        actions.put(":aaa", CryptoAction.DO_NOTHING);
        actions.put("zzz", CryptoAction.ENCRYPT_AND_SIGN);
        actions.put("aa", CryptoAction.ENCRYPT_AND_SIGN);
        actions.put(":zzzz", CryptoAction.DO_NOTHING);
        actions.put("zz", CryptoAction.SIGN_ONLY);

        byte[] legend = encryptLegend(target, actions, List.of(":aaa", ":zzzz"));

        // Canonical Path order (PK, aa, zz, zzz, aaaa) is unchanged by the input
        // permutation, so the sequence is identical to the length-first test.
        byte[] expected = {
            LEGEND_SIGN_ONLY,        // PK
            LEGEND_ENCRYPT_AND_SIGN, // aa
            LEGEND_SIGN_ONLY,        // zz
            LEGEND_ENCRYPT_AND_SIGN, // zzz
            LEGEND_SIGN_ONLY,        // aaaa
        };
        //= specification/structured-encryption/header.md#encrypt-legend-bytes
        //= type=test
        //# The Encrypt Legend Bytes MUST be serialized as follows:
        //#
        //# 1. Order every authenticated attribute in the item by the [Canonical Path](#canonical-path)
        assertArrayEquals(expected, legend,
            "the legend byte order must be determined by Canonical Path, identical to the "
                + "length-first test despite a different schema input order (" + target + ")");
    }

    /**
     * Encrypt an item on {@code target}'s server (a v1 AWS-KMS client for
     * {@code actions}) and return the header's Encrypt Legend bytes. The
     * plaintext carries a value for every declared attribute so that every
     * authenticated attribute is present in the encrypted item.
     */
    private static byte[] encryptLegend(
            LanguageServerTarget target,
            Map<String, CryptoAction> actions,
            List<String> allowedUnsigned) {
        DBESDKTestServerClient client = DbeTestServerClients.forEndpoint(target.endpoint());
        String clientId = newKmsClient(client, TABLE, PK, actions, allowedUnsigned);
        Map<String, AttributeValue> item = new LinkedHashMap<>();
        for (String name : actions.keySet()) {
            item.put(name, AttributeValue.builder().s("v-" + name).build());
        }
        return encryptLegendBytes(encryptOnce(client, clientId, item));
    }
}
