package aws.cryptography.dbesdk.testserver.tests.wire;

import aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers;
import aws.cryptography.dbesdk.testserver.tests.DbeTestServerClients;

import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.HEAD;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.PK;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.TABLE;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.bytesOf;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.canonicalPlaintext;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.encryptOnce;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.newKmsClient;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.resolveKmsKeyArn;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.standardActions;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import aws.cryptography.dbesdk.testserver.client.client.DBESDKTestServerClient;
import aws.cryptography.dbesdk.testserver.client.model.AttributeValue;
import aws.cryptography.dbesdk.testserver.client.model.AwsKmsHierarchicalKeyringConfig;
import aws.cryptography.dbesdk.testserver.client.model.DdbKeyBranchKeyIdSupplier;
import aws.cryptography.dbesdk.testserver.client.model.AwsKmsKeyringConfig;
import aws.cryptography.dbesdk.testserver.client.model.AwsKmsRsaKeyringConfig;
import aws.cryptography.dbesdk.testserver.client.model.CreateClientInput;
import aws.cryptography.dbesdk.testserver.client.model.DBEAlgorithmSuiteId;
import aws.cryptography.dbesdk.testserver.client.model.DBEClientConfig;
import aws.cryptography.dbesdk.testserver.client.model.DBESDKClientError;
import aws.cryptography.dbesdk.testserver.client.model.DBESDKTestServerException;
import aws.cryptography.dbesdk.testserver.client.model.EncryptedDataKeyDescription;
import aws.cryptography.dbesdk.testserver.client.model.EncryptedDataKeyDescriptionSource;
import aws.cryptography.dbesdk.testserver.client.model.GetEncryptedDataKeyDescriptionInput;
import aws.cryptography.dbesdk.testserver.client.model.Keyring;
import aws.cryptography.dbesdk.testserver.client.model.KmsRsaEncryptionAlgorithm;
import aws.cryptography.dbesdk.testserver.client.model.MultiKeyringConfig;
import aws.cryptography.dbesdk.testserver.client.model.PaddingScheme;
import aws.cryptography.dbesdk.testserver.client.model.RawRsaKeyringConfig;
import aws.cryptography.testserver.tests.FeatureGate;
import aws.cryptography.testserver.tests.LanguageServerTarget;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.ByteBuffer;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Cross-language coverage for the {@code GetEncryptedDataKeyDescription} product
 * operation (Dafny {@code DynamoDbGetEncryptedDataKeyDescriptionTest.dfy}). The
 * operation parses the Encrypted Data Keys out of a serialized structured
 * header — supplied directly (the {@code header} union arm) or read from an
 * encrypted item's {@code aws_dbe_head} attribute (the {@code item} arm) — and
 * returns one description per EDK. It uses no CMM/keyring and is deterministic,
 * so it is target-local: each case runs once per target.
 *
 * <p>The baseline cases produce the header on the same target with an ordinary
 * AWS-KMS {@code EncryptItem}, so the description's {@code keyProviderId} is
 * {@code aws-kms} and its {@code keyProviderInfo} is the KMS key ARN the item
 * was wrapped under. The header/item arms are distinct code paths (the item arm
 * first extracts the header attribute), and a missing header attribute is a
 * rejected input.
 *
 * <p>The keyring-family cases below cover the other EDK provider ids the Dafny
 * suite exercises — {@code aws-kms-hierarchy}, {@code aws-kms-rsa},
 * {@code raw-rsa}, and a multi-keyring item with several EDKs — each by
 * producing a real header/item under that keyring family and describing it.
 */
class EncryptedDataKeyDescriptionTests {

    static Stream<LanguageServerTarget> targets() {
        return DbeTestHelpers.targets().stream();
    }

    /** Encrypt the canonical item under AWS-KMS on {@code target}, return the encrypted item. */
    private static Map<String, AttributeValue> encryptedItem(LanguageServerTarget target) {
        DBESDKTestServerClient client = DbeTestServerClients.forEndpoint(target.endpoint());
        String clientId = newKmsClient(client, TABLE, PK, standardActions(), List.of());
        return encryptOnce(client, clientId, canonicalPlaintext());
    }

    private static void assertSingleAwsKmsDescription(
            List<EncryptedDataKeyDescription> descriptions, LanguageServerTarget target) {
        assertEquals(1, descriptions.size(),
            "one description per EDK expected for a single-keyring item on " + target);
        EncryptedDataKeyDescription only = descriptions.get(0);
        //= specification/dynamodb-encryption-client/ddb-get-encrypted-data-key-description.md#behavior
        //= type=test
        //# For every Data Key in Data Keys, the operation MUST attempt to extract a description of the Data Key.
        assertEquals("aws-kms", only.getKeyProviderId(),
            "an AWS-KMS EDK must report keyProviderId=aws-kms on " + target);
        assertEquals(resolveKmsKeyArn(), only.getKeyProviderInfo(),
            "an AWS-KMS EDK's keyProviderInfo must be the wrapping key ARN on " + target);
    }

    @ParameterizedTest(name = "GetEncryptedDataKeyDescription describes a header blob {0}")
    @MethodSource("targets")
    void awsKmsHeaderVariantDescribesEdk(LanguageServerTarget target) {
        DBESDKTestServerClient client = DbeTestServerClients.forEndpoint(target.endpoint());
        byte[] header = bytesOf(encryptedItem(target).get(HEAD));
        List<EncryptedDataKeyDescription> descriptions = client.getEncryptedDataKeyDescription(
            GetEncryptedDataKeyDescriptionInput.builder()
                .input(EncryptedDataKeyDescriptionSource.builder()
                    .header(ByteBuffer.wrap(header))
                    .build())
                .build()).getDescriptions();
        assertSingleAwsKmsDescription(descriptions, target);
    }

    @ParameterizedTest(name = "GetEncryptedDataKeyDescription describes an encrypted item {0}")
    @MethodSource("targets")
    void awsKmsItemVariantDescribesEdk(LanguageServerTarget target) {
        DBESDKTestServerClient client = DbeTestServerClients.forEndpoint(target.endpoint());
        List<EncryptedDataKeyDescription> descriptions = client.getEncryptedDataKeyDescription(
            GetEncryptedDataKeyDescriptionInput.builder()
                .input(EncryptedDataKeyDescriptionSource.builder()
                    .item(encryptedItem(target))
                    .build())
                .build()).getDescriptions();
        assertSingleAwsKmsDescription(descriptions, target);
    }

    @ParameterizedTest(name = "GetEncryptedDataKeyDescription rejects an item with no header {0}")
    @MethodSource("targets")
    void itemWithoutHeaderRejected(LanguageServerTarget target) {
        DBESDKTestServerClient client = DbeTestServerClients.forEndpoint(target.endpoint());
        // An item that carries no aws_dbe_head attribute. The rejection error
        // class differs by adapter (.NET surfaces DBESDKClientError; java/rust
        // classify the header-not-found failure as GenericServerError), so the
        // assertion is on their common supertype — the mechanism is "rejected".
        Map<String, AttributeValue> headerless = new LinkedHashMap<>();
        headerless.put(PK, AttributeValue.builder().s("no-header").build());
        //= specification/dynamodb-encryption-client/ddb-get-encrypted-data-key-description.md#behavior
        //= type=test
        //# If the input is an encrypted DynamoDB item, it MUST attempt to extract "aws_dbe_head" attribute from the DynamoDB item to get the binary header.
        assertThrows(DBESDKTestServerException.class, () -> client.getEncryptedDataKeyDescription(
            GetEncryptedDataKeyDescriptionInput.builder()
                .input(EncryptedDataKeyDescriptionSource.builder().item(headerless).build())
                .build()),
            "an item without a header attribute must be rejected on " + target);
    }

    // -----------------------------------------------------------------------
    // Keyring-family variants. These need a non-baseline keyring family on the
    // producing server, so they are feature-gated, target-only tests: the client
    // is configured and the describe runs on one target, then its local response
    // is inspected — so each runs once per target, not once per producer/consumer
    // pair. All three servers support these families today.
    // -----------------------------------------------------------------------

    // Live branch-key store + asymmetric RSA key (shared with the materials tests).
    private static final String KEY_STORE_TABLE = "KeyStoreDdbTable";
    private static final String LOGICAL_KEY_STORE_NAME = "KeyStoreDdbTable";
    private static final String KEY_STORE_KMS_KEY_ARN =
        "arn:aws:kms:us-west-2:370957321024:key/9d989aa2-2f9c-438c-a745-cc57d3ad0126";
    private static final String BRANCH_KEY_ID = "040a32a8-3737-4f16-a3ba-bd4449556d73";
    private static final String BRANCH_KEY_ID_B = "005dab41-f654-40a7-8ead-a30cbe201567";
    private static final String RSA_KEY_ARN =
        "arn:aws:kms:us-west-2:370957321024:key/624eeb76-f04e-41e5-a66b-359ff89862a3";
    // The active version of the fixture branch key (BRANCH_KEY_ID) in the shared
    // keystore. Deterministic across targets and runs; changes only if the branch
    // key is rotated, at which point this constant is updated with the new version.
    private static final String BRANCH_KEY_VERSION = "1f44cfe2-4f7c-4af4-8c15-f631916acf66";

    /** Encrypt the canonical item with {@code clientId}, then describe its header. */
    private static List<EncryptedDataKeyDescription> describeEncryptedHeader(
            DBESDKTestServerClient client, String clientId) {
        Map<String, AttributeValue> item = encryptOnce(client, clientId, canonicalPlaintext());
        byte[] header = bytesOf(item.get(HEAD));
        return client.getEncryptedDataKeyDescription(
            GetEncryptedDataKeyDescriptionInput.builder()
                .input(EncryptedDataKeyDescriptionSource.builder()
                    .header(ByteBuffer.wrap(header))
                    .build())
                .build()).getDescriptions();
    }

    private static DBEClientConfig.Builder baseConfig() {
        return DBEClientConfig.builder()
            .logicalTableName(TABLE)
            .partitionKeyName(PK)
            .attributeActionsOnEncrypt(standardActions())
            .allowedUnsignedAttributePrefix(":");
    }

    private static Keyring rsaKeyring() {
        return Keyring.builder()
            .awsKmsRsa(AwsKmsRsaKeyringConfig.builder()
                .kmsKeyId(RSA_KEY_ARN)
                .encryptionAlgorithm(KmsRsaEncryptionAlgorithm.RSAES_OAEP_SHA_256)
                .build())
            .build();
    }

    @ParameterizedTest(name = "GetEncryptedDataKeyDescription reports hierarchy branch-key fields {0}")
    @MethodSource("targets")
    void hierarchyEdkDescribesBranchKeyFields(LanguageServerTarget target) {
        FeatureGate.require(Set.of("aws-kms-hierarchical"), target);
        DBESDKTestServerClient client = DbeTestServerClients.forEndpoint(target.endpoint());
        DBEClientConfig config = baseConfig()
            .keyring(Keyring.builder()
                .awsKmsHierarchical(AwsKmsHierarchicalKeyringConfig.builder()
                    .branchKeyId(BRANCH_KEY_ID)
                    .keyStoreTableName(KEY_STORE_TABLE)
                    .logicalKeyStoreName(LOGICAL_KEY_STORE_NAME)
                    .kmsKeyArn(KEY_STORE_KMS_KEY_ARN)
                    .ttlSeconds(3600)
                    .build())
                .build())
            .build();
        String clientId =
            client.createClient(CreateClientInput.builder().config(config).build()).getClientId();
        List<EncryptedDataKeyDescription> descriptions = describeEncryptedHeader(client, clientId);
        assertEquals(1, descriptions.size(),
            "one description per EDK expected for a hierarchical item on " + target);
        EncryptedDataKeyDescription only = descriptions.get(0);
        assertEquals("aws-kms-hierarchy", only.getKeyProviderId(),
            "a hierarchical EDK must report keyProviderId=aws-kms-hierarchy on " + target);
        assertEquals(BRANCH_KEY_ID, only.getKeyProviderInfo(),
            "a hierarchical EDK's keyProviderInfo must be the branch-key id on " + target);
        assertEquals(BRANCH_KEY_ID, only.getBranchKeyId(),
            "a hierarchical EDK must report its branchKeyId on " + target);
        assertEquals(BRANCH_KEY_VERSION, only.getBranchKeyVersion(),
            "a hierarchical EDK must report the fixture branch key's active version on " + target);
    }

    @ParameterizedTest(name = "hierarchical branchKeyIdSupplier routes each item to its own branch key {0}")
    @MethodSource("targets")
    void branchKeyIdSupplierRoutesPerItemBranchKey(LanguageServerTarget target) {
        FeatureGate.require(Set.of("aws-kms-hierarchical"), target);
        DBESDKTestServerClient client = DbeTestServerClients.forEndpoint(target.endpoint());
        // A declarative DynamoDbKeyBranchKeyIdSupplier: route each item to a branch
        // key by the String value of its partition key — pk "route-A" -> branch key
        // A, pk "route-B" -> branch key B (two distinct branch:ACTIVE keys in the
        // shared keystore). The server builds an IDynamoDbKeyBranchKeyIdSupplier
        // from this config via CreateDynamoDbEncryptionBranchKeyIdSupplier.
        DBEClientConfig config = baseConfig()
            .keyring(Keyring.builder()
                .awsKmsHierarchical(AwsKmsHierarchicalKeyringConfig.builder()
                    .branchKeyIdSupplier(DdbKeyBranchKeyIdSupplier.builder()
                        .routeAttribute(PK)
                        .routes(Map.of("route-A", BRANCH_KEY_ID, "route-B", BRANCH_KEY_ID_B))
                        .build())
                    .keyStoreTableName(KEY_STORE_TABLE)
                    .logicalKeyStoreName(LOGICAL_KEY_STORE_NAME)
                    .kmsKeyArn(KEY_STORE_KMS_KEY_ARN)
                    .ttlSeconds(3600)
                    .build())
                .build())
            .build();
        String clientId =
            client.createClient(CreateClientInput.builder().config(config).build()).getClientId();

        String branchKeyForA = describeBranchKeyForPartition(client, clientId, "route-A");
        String branchKeyForB = describeBranchKeyForPartition(client, clientId, "route-B");

        // Dafny DynamoDbEncryptionBranchKeyIdSupplierTest TestHappyCase: a
        // hierarchical keyring using the supplier wraps each item under the branch
        // key the supplier selects from that item's key content.
        assertEquals(BRANCH_KEY_ID, branchKeyForA,
            "an item whose pk routes to branch key A must be wrapped under A on " + target);
        assertEquals(BRANCH_KEY_ID_B, branchKeyForB,
            "an item whose pk routes to branch key B must be wrapped under B on " + target);
        assertNotEquals(branchKeyForA, branchKeyForB,
            "the supplier must route the two items to DIFFERENT branch keys on " + target);
    }

    /**
     * Encrypt the canonical item with its partition key set to {@code pkValue} on
     * {@code clientId}, then read the resulting item's single EDK branch key id via
     * GetEncryptedDataKeyDescription.
     */
    private static String describeBranchKeyForPartition(
            DBESDKTestServerClient client, String clientId, String pkValue) {
        Map<String, AttributeValue> plaintext = new LinkedHashMap<>(canonicalPlaintext());
        plaintext.put(PK, AttributeValue.builder().s(pkValue).build());
        Map<String, AttributeValue> item = encryptOnce(client, clientId, plaintext);
        List<EncryptedDataKeyDescription> descriptions = client.getEncryptedDataKeyDescription(
            GetEncryptedDataKeyDescriptionInput.builder()
                .input(EncryptedDataKeyDescriptionSource.builder().item(item).build())
                .build()).getDescriptions();
        assertEquals(1, descriptions.size(),
            "one description per EDK expected for a hierarchical item (pk=" + pkValue + ")");
        assertEquals("aws-kms-hierarchy", descriptions.get(0).getKeyProviderId(),
            "a hierarchical EDK must report keyProviderId=aws-kms-hierarchy (pk=" + pkValue + ")");
        return descriptions.get(0).getBranchKeyId();
    }

    @ParameterizedTest(name = "GetEncryptedDataKeyDescription describes an AWS-KMS-RSA EDK {0}")
    @MethodSource("targets")
    void awsKmsRsaEdkDescribesProvider(LanguageServerTarget target) {
        FeatureGate.require(Set.of("aws-kms-rsa"), target);
        DBESDKTestServerClient client = DbeTestServerClients.forEndpoint(target.endpoint());
        DBEClientConfig config = baseConfig()
            .algorithmSuiteId(
                DBEAlgorithmSuiteId.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY_SYMSIG_HMAC_SHA384)
            .keyring(rsaKeyring())
            .build();
        String clientId =
            client.createClient(CreateClientInput.builder().config(config).build()).getClientId();
        List<EncryptedDataKeyDescription> descriptions = describeEncryptedHeader(client, clientId);
        assertEquals(1, descriptions.size(),
            "one description per EDK expected for an AWS-KMS-RSA item on " + target);
        assertEquals("aws-kms-rsa", descriptions.get(0).getKeyProviderId(),
            "an AWS-KMS-RSA EDK must report keyProviderId=aws-kms-rsa on " + target);
        assertEquals(RSA_KEY_ARN, descriptions.get(0).getKeyProviderInfo(),
            "an AWS-KMS-RSA EDK's keyProviderInfo must be the configured RSA key ARN on " + target);
    }

    @ParameterizedTest(name = "GetEncryptedDataKeyDescription describes every EDK of a multi-keyring {0}")
    @MethodSource("targets")
    void multiKeyringDescribesEachEdk(LanguageServerTarget target) {
        FeatureGate.require(Set.of("aws-kms-rsa"), target);
        DBESDKTestServerClient client = DbeTestServerClients.forEndpoint(target.endpoint());
        Keyring awsKms = Keyring.builder()
            .awsKms(AwsKmsKeyringConfig.builder().kmsKeyId(resolveKmsKeyArn()).build())
            .build();
        DBEClientConfig config = baseConfig()
            .algorithmSuiteId(
                DBEAlgorithmSuiteId.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY_SYMSIG_HMAC_SHA384)
            .keyring(Keyring.builder()
                .multi(MultiKeyringConfig.builder()
                    .generator(awsKms)
                    .childKeyrings(List.of(rsaKeyring()))
                    .build())
                .build())
            .build();
        String clientId =
            client.createClient(CreateClientInput.builder().config(config).build()).getClientId();
        List<EncryptedDataKeyDescription> descriptions = describeEncryptedHeader(client, clientId);
        //= specification/dynamodb-encryption-client/ddb-get-encrypted-data-key-description.md#behavior
        //= type=test
        //# For every Data Key in Data Keys, the operation MUST attempt to extract a description of the Data Key.
        // A generator (aws-kms) + one child (aws-kms-rsa) produce two EDKs in that
        // order; assert the ordered list (one description per EDK, in EDK order),
        // not merely set membership.
        assertEquals(2, descriptions.size(),
            "a two-keyring item must yield two EDK descriptions on " + target);
        assertEquals("aws-kms", descriptions.get(0).getKeyProviderId(),
            "the generator EDK must be described first as aws-kms on " + target);
        assertEquals("aws-kms-rsa", descriptions.get(1).getKeyProviderId(),
            "the child EDK must be described second as aws-kms-rsa on " + target);
        assertEquals(resolveKmsKeyArn(), descriptions.get(0).getKeyProviderInfo(),
            "the aws-kms EDK's keyProviderInfo must be the wrapping-key ARN on " + target);
        assertEquals(RSA_KEY_ARN, descriptions.get(1).getKeyProviderInfo(),
            "the aws-kms-rsa EDK's keyProviderInfo must be the configured RSA key ARN on " + target);
    }

    @ParameterizedTest(name = "GetEncryptedDataKeyDescription reports hierarchy fields from an item {0}")
    @MethodSource("targets")
    void hierarchyItemVariantDescribesBranchKeyFields(LanguageServerTarget target) {
        FeatureGate.require(Set.of("aws-kms-hierarchical"), target);
        DBESDKTestServerClient client = DbeTestServerClients.forEndpoint(target.endpoint());
        DBEClientConfig config = baseConfig()
            .keyring(Keyring.builder()
                .awsKmsHierarchical(AwsKmsHierarchicalKeyringConfig.builder()
                    .branchKeyId(BRANCH_KEY_ID)
                    .keyStoreTableName(KEY_STORE_TABLE)
                    .logicalKeyStoreName(LOGICAL_KEY_STORE_NAME)
                    .kmsKeyArn(KEY_STORE_KMS_KEY_ARN)
                    .ttlSeconds(3600)
                    .build())
                .build())
            .build();
        String clientId =
            client.createClient(CreateClientInput.builder().config(config).build()).getClientId();
        // Dafny DynamoDbGetEncryptedDataKeyDescriptionTest TestDDBItemInputAwsKmsHDataKeyCase:
        // the item union arm extracts the header from aws_dbe_head and reports the
        // hierarchy branch-key fields.
        //= specification/dynamodb-encryption-client/ddb-get-encrypted-data-key-description.md#behavior
        //= type=test
        //# For every Data Key in Data Keys, the operation MUST attempt to extract a description of the Data Key.
        List<EncryptedDataKeyDescription> descriptions = describeEncryptedItem(client, clientId);
        assertEquals(1, descriptions.size(),
            "one description per EDK expected for a hierarchical item on " + target);
        EncryptedDataKeyDescription only = descriptions.get(0);
        assertEquals("aws-kms-hierarchy", only.getKeyProviderId(),
            "an item-arm hierarchical EDK must report keyProviderId=aws-kms-hierarchy on " + target);
        assertEquals(BRANCH_KEY_ID, only.getKeyProviderInfo(),
            "an item-arm hierarchical EDK's keyProviderInfo must be the branch-key id on " + target);
        assertEquals(BRANCH_KEY_ID, only.getBranchKeyId(),
            "an item-arm hierarchical EDK must report its branchKeyId on " + target);
        assertEquals(BRANCH_KEY_VERSION, only.getBranchKeyVersion(),
            "an item-arm hierarchical EDK must report the fixture branch key's active version on " + target);
    }

    @ParameterizedTest(name = "GetEncryptedDataKeyDescription describes an AWS-KMS-RSA EDK from an item {0}")
    @MethodSource("targets")
    void awsKmsRsaItemVariantDescribesProvider(LanguageServerTarget target) {
        FeatureGate.require(Set.of("aws-kms-rsa"), target);
        DBESDKTestServerClient client = DbeTestServerClients.forEndpoint(target.endpoint());
        DBEClientConfig config = baseConfig()
            .algorithmSuiteId(
                DBEAlgorithmSuiteId.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY_SYMSIG_HMAC_SHA384)
            .keyring(rsaKeyring())
            .build();
        String clientId =
            client.createClient(CreateClientInput.builder().config(config).build()).getClientId();
        // Dafny DynamoDbGetEncryptedDataKeyDescriptionTest TestDDBItemInputAwsKmsRsaDataKeyCase.
        //= specification/dynamodb-encryption-client/ddb-get-encrypted-data-key-description.md#behavior
        //= type=test
        //# For every Data Key in Data Keys, the operation MUST attempt to extract a description of the Data Key.
        List<EncryptedDataKeyDescription> descriptions = describeEncryptedItem(client, clientId);
        assertEquals(1, descriptions.size(),
            "one description per EDK expected for an AWS-KMS-RSA item on " + target);
        assertEquals("aws-kms-rsa", descriptions.get(0).getKeyProviderId(),
            "an item-arm AWS-KMS-RSA EDK must report keyProviderId=aws-kms-rsa on " + target);
        assertEquals(RSA_KEY_ARN, descriptions.get(0).getKeyProviderInfo(),
            "an item-arm AWS-KMS-RSA EDK's keyProviderInfo must be the configured RSA key ARN on " + target);
    }

    @ParameterizedTest(name = "GetEncryptedDataKeyDescription describes every EDK of a multi-keyring from an item {0}")
    @MethodSource("targets")
    void multiKeyringItemVariantDescribesEachEdk(LanguageServerTarget target) {
        FeatureGate.require(Set.of("aws-kms-rsa"), target);
        DBESDKTestServerClient client = DbeTestServerClients.forEndpoint(target.endpoint());
        Keyring awsKms = Keyring.builder()
            .awsKms(AwsKmsKeyringConfig.builder().kmsKeyId(resolveKmsKeyArn()).build())
            .build();
        DBEClientConfig config = baseConfig()
            .algorithmSuiteId(
                DBEAlgorithmSuiteId.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY_SYMSIG_HMAC_SHA384)
            .keyring(Keyring.builder()
                .multi(MultiKeyringConfig.builder()
                    .generator(awsKms)
                    .childKeyrings(List.of(rsaKeyring()))
                    .build())
                .build())
            .build();
        String clientId =
            client.createClient(CreateClientInput.builder().config(config).build()).getClientId();
        // Dafny DynamoDbGetEncryptedDataKeyDescriptionTest TestDDBItemInputMultiDataKeyCase:
        // the item arm yields one description per EDK in EDK order.
        //= specification/dynamodb-encryption-client/ddb-get-encrypted-data-key-description.md#behavior
        //= type=test
        //# For every Data Key in Data Keys, the operation MUST attempt to extract a description of the Data Key.
        List<EncryptedDataKeyDescription> descriptions = describeEncryptedItem(client, clientId);
        assertEquals(2, descriptions.size(),
            "a two-keyring item must yield two EDK descriptions on " + target);
        assertEquals("aws-kms", descriptions.get(0).getKeyProviderId(),
            "the generator EDK must be described first as aws-kms on " + target);
        assertEquals("aws-kms-rsa", descriptions.get(1).getKeyProviderId(),
            "the child EDK must be described second as aws-kms-rsa on " + target);
        assertEquals(resolveKmsKeyArn(), descriptions.get(0).getKeyProviderInfo(),
            "the aws-kms EDK's keyProviderInfo must be the wrapping-key ARN on " + target);
        assertEquals(RSA_KEY_ARN, descriptions.get(1).getKeyProviderInfo(),
            "the aws-kms-rsa EDK's keyProviderInfo must be the configured RSA key ARN on " + target);
    }

    // -----------------------------------------------------------------------
    // Raw-RSA variant. The keyring uses a checked-in, deterministic RSA key
    // target (src/test/resources/raw-rsa/*.pem) and no live AWS resource, so both
    // source arms (header and item) are exercised. For a raw keyring the EDK's
    // keyProviderId is the key namespace and keyProviderInfo is the key name;
    // the Dafny cases assert keyProviderId == "raw-rsa".
    // -----------------------------------------------------------------------

    private static final String RAW_RSA_NAMESPACE = "raw-rsa";
    private static final String RAW_RSA_KEY_NAME = "dbe-test-rsa-key";

    private static ByteBuffer pem(String resource) {
        try (InputStream in = EncryptedDataKeyDescriptionTests.class.getResourceAsStream(resource)) {
            assertNotNull(in, "missing test resource " + resource);
            return ByteBuffer.wrap(in.readAllBytes());
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    private static Keyring rawRsaKeyring() {
        return Keyring.builder()
            .rawRsa(RawRsaKeyringConfig.builder()
                .keyNamespace(RAW_RSA_NAMESPACE)
                .keyName(RAW_RSA_KEY_NAME)
                .paddingScheme(PaddingScheme.OAEP_SHA256_MGF1)
                .publicKey(pem("/raw-rsa/public.pem"))
                .privateKey(pem("/raw-rsa/private.pem"))
                .build())
            .build();
    }

    /** Encrypt the canonical item with {@code clientId}, then describe the whole item. */
    private static List<EncryptedDataKeyDescription> describeEncryptedItem(
            DBESDKTestServerClient client, String clientId) {
        Map<String, AttributeValue> item = encryptOnce(client, clientId, canonicalPlaintext());
        return client.getEncryptedDataKeyDescription(
            GetEncryptedDataKeyDescriptionInput.builder()
                .input(EncryptedDataKeyDescriptionSource.builder().item(item).build())
                .build()).getDescriptions();
    }

    private static void assertRawRsaDescription(
            List<EncryptedDataKeyDescription> descriptions, LanguageServerTarget target) {
        assertEquals(1, descriptions.size(),
            "one description per EDK expected for a raw-RSA item on " + target);
        EncryptedDataKeyDescription only = descriptions.get(0);
        //= specification/dynamodb-encryption-client/ddb-get-encrypted-data-key-description.md#behavior
        //= type=test
        //# If the Data Key does not belong to AWS Cryptographic Materials Provider Keyring, the operation will only return keyProviderId.
        assertEquals("raw-rsa", only.getKeyProviderId(),
            "a raw-RSA EDK must report keyProviderId=raw-rsa on " + target);
        // Optional-field behavior: unlike an AWS-KMS EDK (whose keyProviderInfo is
        // the wrapping-key ARN), a raw-RSA EDK description leaves keyProviderInfo
        // unset on every target — the describe op surfaces the provider id but not
        // the raw key name.
        assertNull(only.getKeyProviderInfo(),
            "a raw-RSA EDK description must leave keyProviderInfo unset on " + target);
        assertNull(only.getBranchKeyId(),
            "a raw-RSA EDK must not carry a branchKeyId on " + target);
        assertNull(only.getBranchKeyVersion(),
            "a raw-RSA EDK must not carry a branchKeyVersion on " + target);
    }

    @ParameterizedTest(name = "GetEncryptedDataKeyDescription describes a raw-RSA EDK from a header {0}")
    @MethodSource("targets")
    void rawRsaHeaderVariantDescribesEdk(LanguageServerTarget target) {
        FeatureGate.require(Set.of("raw-rsa"), target);
        FeatureGate.requireRawRsaPaddings(Set.of("OAEP_SHA256_MGF1"), target);
        DBESDKTestServerClient client = DbeTestServerClients.forEndpoint(target.endpoint());
        DBEClientConfig config = baseConfig().keyring(rawRsaKeyring()).build();
        String clientId =
            client.createClient(CreateClientInput.builder().config(config).build()).getClientId();
        assertRawRsaDescription(describeEncryptedHeader(client, clientId), target);
    }

    @ParameterizedTest(name = "GetEncryptedDataKeyDescription describes a raw-RSA EDK from an item {0}")
    @MethodSource("targets")
    void rawRsaItemVariantDescribesEdk(LanguageServerTarget target) {
        FeatureGate.require(Set.of("raw-rsa"), target);
        FeatureGate.requireRawRsaPaddings(Set.of("OAEP_SHA256_MGF1"), target);
        DBESDKTestServerClient client = DbeTestServerClients.forEndpoint(target.endpoint());
        DBEClientConfig config = baseConfig().keyring(rawRsaKeyring()).build();
        String clientId =
            client.createClient(CreateClientInput.builder().config(config).build()).getClientId();
        assertRawRsaDescription(describeEncryptedItem(client, clientId), target);
    }
}
