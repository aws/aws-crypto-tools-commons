package aws.cryptography.mpl.testserver.tests;

import static aws.cryptography.mpl.testserver.tests.Materials.bytes;
import static aws.cryptography.mpl.testserver.tests.Materials.edk;
import static aws.cryptography.mpl.testserver.tests.Materials.materialsWithDataKey;
import static aws.cryptography.mpl.testserver.tests.MplErrors.INVALID_CONFIGURATION_ERROR;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import aws.cryptography.mpl.testserver.client.model.AlgorithmSuiteId;
import aws.cryptography.mpl.testserver.client.model.DecryptionMaterials;
import aws.cryptography.mpl.testserver.client.model.Discovery;
import aws.cryptography.mpl.testserver.client.model.EncryptedDataKey;
import aws.cryptography.mpl.testserver.client.model.EncryptionMaterials;
import aws.cryptography.mpl.testserver.client.model.KmsConfiguration;
import aws.cryptography.mpl.testserver.client.model.MRDiscovery;
import aws.cryptography.mpl.testserver.client.model.StaticBranchKeyIdSupplier;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * The AWS KMS Hierarchical keyring, ported from the Dafny MPL's
 * TestAwsKmsHierarchicalKeyring.dfy, driven directly through the keyring
 * interface.
 *
 * <p>The keyring round trips run across the pairwise matrix: OnEncrypt on the
 * encrypt target, OnDecrypt on the decrypt target, each server reading the same
 * pre-provisioned branch keys. The encrypt side's EDK is also checked byte for
 * byte against aws-kms-hierarchical-keyring.md (key provider id
 * "aws-kms-hierarchy"; key provider info = branch key id; ciphertext = salt (16)
 * || IV (12) || branch key version (16) || wrapped key || tag (16)), so two
 * implementations that agree only with each other still fail here.
 *
 * <p>The shared-cache tests run per target: a materials cache lives inside one
 * server process, so sharing it across servers is not a thing a test can ask.
 *
 * <p>These tests are online. Every server needs AWS credentials with DynamoDB
 * GetItem on the branch key store table, and KMS Decrypt on KMS_KEY_ARN, the
 * DISCOVERY_BRANCH_KEY_ID's KMS key, and the us-east-1 and us-west-2 replicas
 * of MRK_ID.
 */
@KeyringFeature("hierarchical")
public class AwsKmsHierarchicalKeyringTest implements KeyringTestDefaults, KeyringContract {

    // Shared branch key store fixtures in the CI-resources account 370957321024,
    // the same ones the Dafny MPL tests use (AwsCryptographyKeyStore/test/Fixtures.dfy).
    // THESE ARE TESTING RESOURCES. DO NOT USE THEM IN A PRODUCTION ENVIRONMENT.
    private static final String KEY_STORE_TABLE_NAME = "KeyStoreDdbTable";
    private static final String LOGICAL_KEY_STORE_NAME = KEY_STORE_TABLE_NAME;
    private static final String KMS_KEY_ARN =
        "arn:aws:kms:us-west-2:370957321024:key/9d989aa2-2f9c-438c-a745-cc57d3ad0126";
    private static final String KEY_STORE_REGION = "us-west-2";
    /** A KMS region other than the KMS key's, so every KMS Decrypt through it fails. */
    private static final String MISMATCHED_KMS_REGION = "us-east-2";

    private static final String BRANCH_KEY_ID = "3f43a9af-08c5-4317-b694-3d3e883dcaef";
    /** BRANCH_KEY_ID's active version, as the native Rust MPL's integ tests also assert. */
    private static final String BRANCH_KEY_ACTIVE_VERSION = "caf0c508-e64d-4b6c-bffe-381cbc546c02";
    private static final String BRANCH_KEY_ID_WITH_EC = "4bb57643-07c1-419e-92ad-0df0df149d7c";

    /**
     * Fixtures.dfy postalHornBranchKeyId: its record names a KMS key other than
     * KMS_KEY_ARN, so only a Discovery key store can serve it.
     */
    private static final String DISCOVERY_BRANCH_KEY_ID = "682dfba7-4c35-491d-8d6a-5a9c56194061";
    private static final String DISCOVERY_BRANCH_KEY_ACTIVE_VERSION =
        "6b7a8ef4-8c1c-4f63-b196-a6ef7e496e50";

    /**
     * Fixtures.dfy MRK fixtures (account 658956600833): EastBranchKey's record
     * names the us-east-1 replica of MRK_ID, WestBranchKey's the us-west-2
     * replica. ap-south-2 has no replica.
     */
    private static final String MRK_ID = "mrk-80bd8ecdcd4342aebd84b7dc9da498a7";
    private static final String MRK_ARN_EAST = "arn:aws:kms:us-east-1:658956600833:key/" + MRK_ID;
    private static final String MRK_ARN_WEST = "arn:aws:kms:us-west-2:658956600833:key/" + MRK_ID;
    private static final String MRK_ARN_AP = "arn:aws:kms:ap-south-2:658956600833:key/" + MRK_ID;
    private static final String EAST_BRANCH_KEY = "MyEastBranch2";
    private static final String WEST_BRANCH_KEY = "MyWestBranch2";

    /** TestBranchKeyIdSupplier's mapping: branchKey=caseA and branchKey=caseB. */
    private static final String SUPPLIER_EC_KEY = "branchKey";
    private static final String CASE_A = "caseA";
    private static final String CASE_B = "caseB";
    private static final Map<String, String> SUPPLIER_MAPPING =
        Map.of(CASE_A, BRANCH_KEY_ID, CASE_B, BRANCH_KEY_ID_WITH_EC);

    /** 600 seconds, as the Dafny tests use. */
    private static final int TTL_SECONDS = 600;

    /** The Dafny tests' TEST_ESDK_ALG_SUITE_ID: non-signing, 32-byte data key. */
    private static final AlgorithmSuiteId SUITE =
        AlgorithmSuiteId.ALG_AES_256_GCM_IV12_TAG16_NO_KDF;
    private static final int DATA_KEY_LENGTH = 32;

    /** TestUtils.SmallEncryptionContext(A). */
    private static final Map<String, String> EC = Map.of("keyA", "valA");

    private static final String PROVIDER_ID = "aws-kms-hierarchy";
    private static final int SALT_LENGTH = 16;
    private static final int IV_LENGTH = 12;
    private static final int VERSION_LENGTH = 16;
    private static final int TAG_LENGTH = 16;

    @Override
    public AlgorithmSuiteId algorithmSuite() {
        return SUITE;
    }

    @Override
    public Map<String, String> encryptionContext() {
        return EC;
    }

    static List<String> supplierCases() {
        return List.of(CASE_A, CASE_B);
    }

    // -----------------------------------------------------------------------
    // TestHierarchyClientESDKSuite
    // -----------------------------------------------------------------------

    @KeyringTest(name = "[hierarchical] OnEncrypt/OnDecrypt {0}", pairs = true)
    void onEncryptOnDecryptRoundTrip(Mpl encryptingMpl, Mpl decryptingMpl) {
        EncryptionMaterials encrypted =
            hierarchyKeyring(encryptingMpl).onEncrypt(encryptingMpl.newEncryptionMaterials());

        assertEquals(DATA_KEY_LENGTH, bytes(encrypted.getPlaintextDataKey()).length);
        assertEquals(1, encrypted.getEncryptedDataKeys().size());
        EncryptedDataKey edk = encrypted.getEncryptedDataKeys().get(0);
        assertHierarchyEdk(edk, BRANCH_KEY_ID);
        assertArrayEquals(uuidBytes(BRANCH_KEY_ACTIVE_VERSION), versionBytes(edk),
            "the EDK carries the branch key's active version");

        DecryptionMaterials decrypted = hierarchyKeyring(decryptingMpl)
            .onDecrypt(decryptingMpl.newDecryptionMaterials(), encrypted.getEncryptedDataKeys());

        assertArrayEquals(bytes(encrypted.getPlaintextDataKey()), bytes(decrypted.getPlaintextDataKey()));
    }

    /**
     * Materials that already hold a data key: OnEncrypt must wrap that key, not
     * generate a new one. The Dafny test uses an all-zero key.
     */
    @KeyringTest(name = "[hierarchical] wrap existing data key {0}", pairs = true)
    void onEncryptWrapsExistingDataKey(Mpl encryptingMpl, Mpl decryptingMpl) {
        byte[] zeroedKey = new byte[DATA_KEY_LENGTH];

        EncryptionMaterials withKey = materialsWithDataKey(encryptingMpl.newEncryptionMaterials(), zeroedKey);
        EncryptionMaterials encrypted = hierarchyKeyring(encryptingMpl).onEncrypt(withKey);

        assertArrayEquals(zeroedKey, bytes(encrypted.getPlaintextDataKey()),
            "wrapping an existing data key must not replace it");
        assertEquals(1, encrypted.getEncryptedDataKeys().size());
        assertHierarchyEdk(encrypted.getEncryptedDataKeys().get(0), BRANCH_KEY_ID);

        DecryptionMaterials decrypted = hierarchyKeyring(decryptingMpl)
            .onDecrypt(decryptingMpl.newDecryptionMaterials(), encrypted.getEncryptedDataKeys());

        assertArrayEquals(zeroedKey, bytes(decrypted.getPlaintextDataKey()));
    }

    // -----------------------------------------------------------------------
    // TestBranchKeyIdSupplier / TestInvalidDataKeyError
    // -----------------------------------------------------------------------

    /** The supplier picks the branch key from the encryption context, on both sides. */
    @KeyringTest(
        name = "[hierarchical] supplier {0} {1}",
        inputs = "supplierCases",
        pairs = true)
    void supplierSelectsBranchKeyFromContext(String supplierCase, Mpl encryptingMpl, Mpl decryptingMpl) {
        Map<String, String> ec = withSupplierCase(supplierCase);

        EncryptionMaterials encrypted =
            supplierKeyring(encryptingMpl).onEncrypt(encryptingMpl.newEncryptionMaterials(ec));

        assertEquals(1, encrypted.getEncryptedDataKeys().size());
        assertHierarchyEdk(encrypted.getEncryptedDataKeys().get(0), SUPPLIER_MAPPING.get(supplierCase));

        DecryptionMaterials decrypted = supplierKeyring(decryptingMpl)
            .onDecrypt(decryptingMpl.newDecryptionMaterials(ec), encrypted.getEncryptedDataKeys());

        assertArrayEquals(bytes(encrypted.getPlaintextDataKey()), bytes(decrypted.getPlaintextDataKey()));
    }

    /**
     * Encrypt under case A, decrypt with a case B context: the supplier picks the
     * other branch key, whose id does not match the EDK's, so no EDK decrypts.
     */
    @KeyringTest(name = "[hierarchical] supplier picks a non-matching branch key {0}", pairs = true)
    void onDecryptWithNonMatchingSuppliedBranchKeyFails(Mpl encryptingMpl, Mpl decryptingMpl) {
        EncryptionMaterials encrypted = supplierKeyring(encryptingMpl)
            .onEncrypt(encryptingMpl.newEncryptionMaterials(withSupplierCase(CASE_A)));

        Keyring keyring = supplierKeyring(decryptingMpl);
        DecryptionMaterials caseB = decryptingMpl.newDecryptionMaterials(withSupplierCase(CASE_B));
        keyring.onDecryptFails(caseB, encrypted.getEncryptedDataKeys());
    }

    /** DummyBranchKeyIdSupplier fails for a context it has no mapping for. */
    @KeyringTest(name = "[hierarchical] supplier with no mapping for the context fails {0}")
    void supplierWithNoMappingFails(Mpl mpl) {
        Keyring keyring = supplierKeyring(mpl);
        keyring.onEncryptFails(mpl.newEncryptionMaterials());
    }

    // -----------------------------------------------------------------------
    // Construction (AwsCryptographyMaterialProvidersOperations.dfy)
    // -----------------------------------------------------------------------

    @KeyringTest(name = "[hierarchical] both branch key id and supplier rejected {0}")
    void bothBranchKeyIdAndSupplierRejected(Mpl mpl) {
        String keyStoreId = keyStore(mpl, KEY_STORE_REGION, LOGICAL_KEY_STORE_NAME);

        // Accepts a branch key id alone: the keyring encrypts a data key and decrypts it again
        Keyring keyring = mpl.hierarchicalKeyring()
            .keyStoreId(keyStoreId)
            .branchKeyId(BRANCH_KEY_ID)
            .ttlSeconds(TTL_SECONDS)
            .create();
        EncryptionMaterials encrypted = keyring.onEncrypt(mpl.newEncryptionMaterials());
        DecryptionMaterials decrypted =
            keyring.onDecrypt(mpl.newDecryptionMaterials(), encrypted.getEncryptedDataKeys());
        assertEquals(encrypted.getPlaintextDataKey(), decrypted.getPlaintextDataKey());
        // Rejects a branch key id and a supplier together
        mpl.hierarchicalKeyring()
            .keyStoreId(keyStoreId)
            .branchKeyId(BRANCH_KEY_ID)
            .branchKeyIdSupplier(supplier())
            .ttlSeconds(TTL_SECONDS)
            .createFailsWith(INVALID_CONFIGURATION_ERROR);
    }

    @KeyringTest(name = "[hierarchical] neither branch key id nor supplier rejected {0}")
    void neitherBranchKeyIdNorSupplierRejected(Mpl mpl) {
        String keyStoreId = keyStore(mpl, KEY_STORE_REGION, LOGICAL_KEY_STORE_NAME);

        mpl.hierarchicalKeyring()
            .keyStoreId(keyStoreId)
            .ttlSeconds(TTL_SECONDS)
            .createFails();
    }

    // -----------------------------------------------------------------------
    // TestSharedCache*
    //
    // HK1's key store reaches KMS in the key's region; HK2's key store reaches
    // KMS in another region, so HK2 can only succeed by reading branch key
    // materials HK1 put in the shared cache. HK2 succeeding after HK1 proves a
    // cache hit; HK2 still failing proves a miss.
    // -----------------------------------------------------------------------

    @KeyringTest(name = "[hierarchical] shared cache, same partition, same logical name: hit {0}")
    void sharedCacheSamePartitionSameLogicalNameHits(Mpl mpl) {
        String cacheId = mpl.sharedCache(100);
        Keyring hk1 = sharedCacheKeyring(mpl, KEY_STORE_REGION, LOGICAL_KEY_STORE_NAME, cacheId, "partitionId");
        Keyring hk2 = sharedCacheKeyring(mpl, MISMATCHED_KMS_REGION, LOGICAL_KEY_STORE_NAME, cacheId, "partitionId");

        hk2.onEncryptFails(mpl.newEncryptionMaterials());
        roundTripOnOneTarget(mpl, hk1);
        roundTripOnOneTarget(mpl, hk2);
    }

    @KeyringTest(name = "[hierarchical] shared cache, unspecified partitions: miss {0}")
    void sharedCacheUnspecifiedPartitionsMiss(Mpl mpl) {
        String cacheId = mpl.sharedCache(100);
        Keyring hk1 = sharedCacheKeyring(mpl, KEY_STORE_REGION, LOGICAL_KEY_STORE_NAME, cacheId, null);
        Keyring hk2 = sharedCacheKeyring(mpl, MISMATCHED_KMS_REGION, LOGICAL_KEY_STORE_NAME, cacheId, null);

        assertSharedCacheMiss(mpl, hk1, hk2);
    }

    @KeyringTest(name = "[hierarchical] shared cache, different partitions: miss {0}")
    void sharedCacheDifferentPartitionsMiss(Mpl mpl) {
        String cacheId = mpl.sharedCache(100);
        Keyring hk1 = sharedCacheKeyring(mpl, KEY_STORE_REGION, LOGICAL_KEY_STORE_NAME, cacheId, "partitionIdHK1");
        Keyring hk2 = sharedCacheKeyring(mpl, MISMATCHED_KMS_REGION, LOGICAL_KEY_STORE_NAME, cacheId, "partitionIdHK2");

        assertSharedCacheMiss(mpl, hk1, hk2);
    }

    @KeyringTest(name = "[hierarchical] shared cache, same partition, different logical name: miss {0}")
    void sharedCacheDifferentLogicalNameMiss(Mpl mpl) {
        String cacheId = mpl.sharedCache(100);
        Keyring hk1 = sharedCacheKeyring(mpl, KEY_STORE_REGION, LOGICAL_KEY_STORE_NAME, cacheId, "partitionId");
        Keyring hk2 = sharedCacheKeyring(mpl, MISMATCHED_KMS_REGION, LOGICAL_KEY_STORE_NAME + "New",
            cacheId, "partitionId");

        assertSharedCacheMiss(mpl, hk1, hk2);
    }

    // -----------------------------------------------------------------------
    // Key store KMS configuration (TestDiscoveryGetKeys.dfy, TestGetKeys.dfy
    // TestGetActiveMrkKey)
    //
    // The Dafny tests call the key store directly. Here the keyring drives it:
    // OnEncrypt reads the active branch key and OnDecrypt reads the version the
    // EDK names, so each configuration is exercised on both key store reads.
    // -----------------------------------------------------------------------

    /** A key store configuration, its KMS client region, and a branch key it can serve. */
    record KeyStoreCase(String name, KmsConfiguration kmsConfiguration, String kmsRegion,
            String branchKeyId) {
        @Override
        public String toString() {
            return name;
        }
    }

    static List<KeyStoreCase> servingCases() {
        return List.of(
            // TestDiscoveryGetKeys: one Discovery key store serves branch keys
            // under two different KMS keys.
            new KeyStoreCase("discovery, " + BRANCH_KEY_ID, discovery(), KEY_STORE_REGION, BRANCH_KEY_ID),
            new KeyStoreCase("discovery, discovery branch key", discovery(), KEY_STORE_REGION,
                DISCOVERY_BRANCH_KEY_ID),
            // TestGetKeysForMrk: MRDiscovery rewrites the record's us-east-1 ARN
            // into us-west-2, reaching the replica.
            new KeyStoreCase("mrDiscovery us-west-2, east branch key", mrDiscovery(KEY_STORE_REGION),
                KEY_STORE_REGION, EAST_BRANCH_KEY),
            // TestGetActiveMrkKey: every configuration works when regions match.
            new KeyStoreCase("kmsKeyArn west, west branch key", kmsKeyArn(MRK_ARN_WEST),
                "us-west-2", WEST_BRANCH_KEY),
            new KeyStoreCase("kmsKeyArn east, east branch key", kmsKeyArn(MRK_ARN_EAST),
                "us-east-1", EAST_BRANCH_KEY),
            new KeyStoreCase("kmsMRKeyArn west, west branch key", kmsMRKeyArn(MRK_ARN_WEST),
                "us-west-2", WEST_BRANCH_KEY),
            new KeyStoreCase("kmsMRKeyArn east, east branch key", kmsMRKeyArn(MRK_ARN_EAST),
                "us-east-1", EAST_BRANCH_KEY),
            // ... and an MRK configuration also serves the other region's record.
            new KeyStoreCase("kmsMRKeyArn west, east branch key", kmsMRKeyArn(MRK_ARN_WEST),
                "us-west-2", EAST_BRANCH_KEY),
            new KeyStoreCase("kmsMRKeyArn east, west branch key", kmsMRKeyArn(MRK_ARN_EAST),
                "us-east-1", WEST_BRANCH_KEY));
    }

    static List<KeyStoreCase> rejectingCases() {
        return List.of(
            // A key store pinned to KMS_KEY_ARN rejects a record naming another key.
            new KeyStoreCase("kmsKeyArn, discovery branch key", kmsKeyArn(KMS_KEY_ARN), KEY_STORE_REGION,
                DISCOVERY_BRANCH_KEY_ID),
            // TestGetKeysForMrk: plain Discovery passes the us-east-1 ARN to a
            // us-west-2 client.
            new KeyStoreCase("discovery, east branch key", discovery(), KEY_STORE_REGION,
                EAST_BRANCH_KEY),
            // TestGetActiveMrkKey: a single-region configuration rejects the
            // other replica's record.
            new KeyStoreCase("kmsKeyArn west, east branch key", kmsKeyArn(MRK_ARN_WEST),
                "us-west-2", EAST_BRANCH_KEY),
            new KeyStoreCase("kmsKeyArn east, west branch key", kmsKeyArn(MRK_ARN_EAST),
                "us-east-1", WEST_BRANCH_KEY),
            // ... and an MRK configuration in a region with no replica fails.
            new KeyStoreCase("kmsMRKeyArn ap-south-2, west branch key", kmsMRKeyArn(MRK_ARN_AP),
                "ap-south-2", WEST_BRANCH_KEY));
    }

    @KeyringTest(
        name = "[hierarchical] key store {0} round trip {1}",
        inputs = "servingCases",
        pairs = true)
    void keyStoreConfigurationServesBranchKey(KeyStoreCase keyStoreCase, Mpl encryptingMpl, Mpl decryptingMpl) {
        EncryptionMaterials encrypted = keyStoreCaseKeyring(encryptingMpl, keyStoreCase)
            .onEncrypt(encryptingMpl.newEncryptionMaterials());

        assertEquals(1, encrypted.getEncryptedDataKeys().size());
        EncryptedDataKey edk = encrypted.getEncryptedDataKeys().get(0);
        assertHierarchyEdk(edk, keyStoreCase.branchKeyId());
        if (keyStoreCase.branchKeyId().equals(DISCOVERY_BRANCH_KEY_ID)) {
            assertArrayEquals(uuidBytes(DISCOVERY_BRANCH_KEY_ACTIVE_VERSION), versionBytes(edk),
                "the EDK carries the branch key's active version");
        }

        DecryptionMaterials decrypted = keyStoreCaseKeyring(decryptingMpl, keyStoreCase)
            .onDecrypt(decryptingMpl.newDecryptionMaterials(), encrypted.getEncryptedDataKeys());

        assertArrayEquals(bytes(encrypted.getPlaintextDataKey()), bytes(decrypted.getPlaintextDataKey()));
    }

    @KeyringTest(
        name = "[hierarchical] key store {0} rejects the branch key {1}",
        inputs = "rejectingCases")
    void keyStoreConfigurationRejectsBranchKey(KeyStoreCase keyStoreCase, Mpl mpl) {
        keyStoreCaseKeyring(mpl, keyStoreCase).onEncryptFails(mpl.newEncryptionMaterials());
    }

    // -----------------------------------------------------------------------
    // Checks every keyring must pass
    // -----------------------------------------------------------------------

    @Override
    public Keyring workingKeyring(Mpl mpl) {
        return hierarchyKeyring(mpl);
    }

    /** One EDK for another provider and one for another branch key. */
    @Override
    public List<EncryptedDataKey> edksThatDontMatch() {
        return List.of(
            edk("raw-aes", BRANCH_KEY_ID, 1),
            edk(PROVIDER_ID, BRANCH_KEY_ID_WITH_EC, 2));
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    private static void assertSharedCacheMiss(Mpl mpl, Keyring hk1, Keyring hk2) {
        hk2.onEncryptFails(mpl.newEncryptionMaterials());
        roundTripOnOneTarget(mpl, hk1);
        hk2.onEncryptFails(mpl.newEncryptionMaterials());
    }

    /** The Dafny TestRoundtrip: OnEncrypt then OnDecrypt with one keyring. */
    private static void roundTripOnOneTarget(Mpl mpl, Keyring keyring) {
        EncryptionMaterials encrypted = keyring.onEncrypt(mpl.newEncryptionMaterials());
        assertEquals(1, encrypted.getEncryptedDataKeys().size());
        assertHierarchyEdk(encrypted.getEncryptedDataKeys().get(0), BRANCH_KEY_ID);
        DecryptionMaterials decrypted =
            keyring.onDecrypt(mpl.newDecryptionMaterials(), encrypted.getEncryptedDataKeys());
        assertArrayEquals(bytes(encrypted.getPlaintextDataKey()), bytes(decrypted.getPlaintextDataKey()));
    }

    private static void assertHierarchyEdk(EncryptedDataKey edk, String branchKeyId) {
        assertEquals(PROVIDER_ID, edk.getKeyProviderId());
        assertArrayEquals(branchKeyId.getBytes(StandardCharsets.UTF_8), bytes(edk.getKeyProviderInfo()),
            "key provider info is the branch key id");
        assertEquals(SALT_LENGTH + IV_LENGTH + VERSION_LENGTH + DATA_KEY_LENGTH + TAG_LENGTH,
            bytes(edk.getCiphertext()).length,
            "ciphertext is salt || IV || version || wrapped key || tag");
    }

    private static byte[] versionBytes(EncryptedDataKey edk) {
        int start = SALT_LENGTH + IV_LENGTH;
        return Arrays.copyOfRange(bytes(edk.getCiphertext()), start, start + VERSION_LENGTH);
    }

    /** The 16-byte big-endian form of a UUID string. */
    private static byte[] uuidBytes(String uuid) {
        UUID parsed = UUID.fromString(uuid);
        return ByteBuffer.allocate(16)
            .putLong(parsed.getMostSignificantBits())
            .putLong(parsed.getLeastSignificantBits())
            .array();
    }

    private static Map<String, String> withSupplierCase(String supplierCase) {
        Map<String, String> ec = new HashMap<>(EC);
        ec.put(SUPPLIER_EC_KEY, supplierCase);
        return ec;
    }

    private static StaticBranchKeyIdSupplier supplier() {
        return StaticBranchKeyIdSupplier.builder()
            .encryptionContextKey(SUPPLIER_EC_KEY)
            .branchKeyIds(SUPPLIER_MAPPING)
            .build();
    }

    private static String keyStore(Mpl mpl, String kmsRegion, String logicalName) {
        return keyStore(mpl, kmsKeyArn(KMS_KEY_ARN), kmsRegion, logicalName);
    }

    private static String keyStore(Mpl mpl, KmsConfiguration kmsConfiguration, String kmsRegion,
            String logicalName) {
        return mpl.keyStore()
            .ddbTableName(KEY_STORE_TABLE_NAME)
            .logicalKeyStoreName(logicalName)
            .kmsConfiguration(kmsConfiguration)
            .kmsClientRegion(kmsRegion)
            .ddbClientRegion(KEY_STORE_REGION)
            .create();
    }

    private static KmsConfiguration kmsKeyArn(String arn) {
        return KmsConfiguration.builder().kmsKeyArn(arn).build();
    }

    private static KmsConfiguration kmsMRKeyArn(String arn) {
        return KmsConfiguration.builder().kmsMRKeyArn(arn).build();
    }

    private static KmsConfiguration discovery() {
        return KmsConfiguration.builder().discovery(Discovery.builder().build()).build();
    }

    private static KmsConfiguration mrDiscovery(String region) {
        return KmsConfiguration.builder()
            .mrDiscovery(MRDiscovery.builder().region(region).build())
            .build();
    }

    private static Keyring keyStoreCaseKeyring(Mpl mpl, KeyStoreCase keyStoreCase) {
        String keyStoreId = keyStore(mpl, keyStoreCase.kmsConfiguration(), keyStoreCase.kmsRegion(),
            LOGICAL_KEY_STORE_NAME);
        return mpl.hierarchicalKeyring()
            .keyStoreId(keyStoreId)
            .branchKeyId(keyStoreCase.branchKeyId())
            .ttlSeconds(TTL_SECONDS)
            .create();
    }

    private static Keyring hierarchyKeyring(Mpl mpl) {
        String keyStoreId = keyStore(mpl, KEY_STORE_REGION, LOGICAL_KEY_STORE_NAME);
        return mpl.hierarchicalKeyring()
            .keyStoreId(keyStoreId)
            .branchKeyId(BRANCH_KEY_ID)
            .ttlSeconds(TTL_SECONDS)
            .create();
    }

    private static Keyring supplierKeyring(Mpl mpl) {
        String keyStoreId = keyStore(mpl, KEY_STORE_REGION, LOGICAL_KEY_STORE_NAME);
        return mpl.hierarchicalKeyring()
            .keyStoreId(keyStoreId)
            .branchKeyIdSupplier(supplier())
            .ttlSeconds(TTL_SECONDS)
            .create();
    }

    /** @param partitionId the partition, or null to let the MPL generate one. */
    private static Keyring sharedCacheKeyring(Mpl mpl, String kmsRegion, String logicalName, String cacheId,
            String partitionId) {
        String keyStoreId = keyStore(mpl, kmsRegion, logicalName);
        Mpl.HierarchicalKeyringBuilder builder = mpl.hierarchicalKeyring()
            .keyStoreId(keyStoreId)
            .branchKeyId(BRANCH_KEY_ID)
            .ttlSeconds(TTL_SECONDS)
            .cacheId(cacheId);
        return (partitionId == null ? builder : builder.partitionId(partitionId)).create();
    }
}
