$version: "2.0"

namespace aws.cryptography.mpl.testserver

use smithy.protocols#rpcv2Cbor

/// The MPL TestServer service. A single hand-written Smithy 2.0 model
/// is the source of truth for the wire contract shared by every Language_Server.
///
/// Unlike the ESDK TestServer (which exercises encrypt/decrypt end-to-end),
/// the MPL TestServer exercises the Material Providers Library itself: keyring
/// and CMM construction, the keyring interface (OnEncrypt / OnDecrypt), and
/// CMM materials retrieval.
///
/// Scope is the MPL surface every configured Language_Server implements: the
/// Raw AES keyring, the AWS KMS Hierarchical keyring with its key store and
/// materials cache, and the Default CMM, over ESDK algorithm suites only.
/// Keyrings, CMMs, and suite formats a server does not implement are not
/// modeled.
///
/// Every Create* operation returns an opaque ResourceId into a server-side
/// registry, because a keyring, CMM, key store, or materials cache cannot cross
/// the wire. Every operation on a created resource takes that id back. A server
/// MUST answer an absent, unknown, or wrong-kind id with GenericServerError.
///
/// Errors travel as the rpcv2Cbor body `{"__type": <shape id>, "message": ...}`
/// with HTTP 400, where <shape id> is exactly
/// `aws.cryptography.mpl.testserver#GenericServerError` or
/// `aws.cryptography.mpl.testserver#MPLClientError`.
@rpcv2Cbor
service MPLTestServer {
    version: "2026-09-28"
    operations: [
        CreateRawAesKeyring
        CreateKeyStoreClient
        CreateCryptographicMaterialsCache
        CreateAwsKmsHierarchicalKeyring
        CreateDefaultCmm
        InitializeEncryptionMaterials
        InitializeDecryptionMaterials
        OnEncrypt
        OnDecrypt
        GetEncryptionMaterials
        DecryptMaterials
    ]
    errors: [
        GenericServerError
        MPLClientError
    ]
}

// ===========================================================================
// Operations
// ===========================================================================

/// Construct and register a Raw AES keyring, returning its handle.
operation CreateRawAesKeyring {
    input: CreateRawAesKeyringRequest
    output: CreateRawAesKeyringResponse
    errors: [GenericServerError, MPLClientError]
}

/// Construct and register a key store client over an existing DynamoDB branch
/// key store table, returning its handle. This constructs the KeyStore; it is
/// not the KeyStore's CreateKeyStore operation, which creates the table.
operation CreateKeyStoreClient {
    input: CreateKeyStoreClientRequest
    output: CreateKeyStoreClientResponse
    errors: [GenericServerError, MPLClientError]
}

/// Construct and register a materials cache, returning its handle. A cache
/// handle passed to more than one hierarchical keyring is shared between them.
operation CreateCryptographicMaterialsCache {
    input: CreateCryptographicMaterialsCacheRequest
    output: CreateCryptographicMaterialsCacheResponse
    errors: [GenericServerError, MPLClientError]
}

/// Construct and register an AWS KMS Hierarchical keyring over a
/// previously-registered key store, returning its handle.
operation CreateAwsKmsHierarchicalKeyring {
    input: CreateAwsKmsHierarchicalKeyringRequest
    output: CreateAwsKmsHierarchicalKeyringResponse
    errors: [GenericServerError, MPLClientError]
}

/// Construct and register a Default CMM wrapping a previously-registered
/// keyring, returning its handle.
operation CreateDefaultCmm {
    input: CreateDefaultCmmRequest
    output: CreateDefaultCmmResponse
    errors: [GenericServerError, MPLClientError]
}

/// Produce well-formed encryption materials with no data key, for input to
/// OnEncrypt. Exposed so a test never hand-builds materials: hand-built
/// materials would encode the harness's idea of well-formed rather than the
/// MPL's.
operation InitializeEncryptionMaterials {
    input: InitializeEncryptionMaterialsRequest
    output: InitializeEncryptionMaterialsResponse
    errors: [GenericServerError, MPLClientError]
}

/// Produce well-formed decryption materials with no data key, for input to
/// OnDecrypt.
operation InitializeDecryptionMaterials {
    input: InitializeDecryptionMaterialsRequest
    output: InitializeDecryptionMaterialsResponse
    errors: [GenericServerError, MPLClientError]
}

/// Invoke a registered keyring's OnEncrypt.
operation OnEncrypt {
    input: OnEncryptRequest
    output: OnEncryptResponse
    errors: [GenericServerError, MPLClientError]
}

/// Invoke a registered keyring's OnDecrypt.
operation OnDecrypt {
    input: OnDecryptRequest
    output: OnDecryptResponse
    errors: [GenericServerError, MPLClientError]
}

/// Retrieve encryption materials from a previously-registered CMM.
operation GetEncryptionMaterials {
    input: GetEncryptionMaterialsRequest
    output: GetEncryptionMaterialsResponse
    errors: [GenericServerError, MPLClientError]
}

/// Retrieve decryption materials from a previously-registered CMM.
operation DecryptMaterials {
    input: DecryptMaterialsRequest
    output: DecryptMaterialsResponse
    errors: [GenericServerError, MPLClientError]
}

// ===========================================================================
// Enumerations
// ===========================================================================

/// AES wrapping algorithm for the Raw AES keyring.
enum AesWrappingAlg {
    ALG_AES128_GCM_IV12_TAG16
    ALG_AES192_GCM_IV12_TAG16
    ALG_AES256_GCM_IV12_TAG16
}

/// Commitment policy (ESDK format only).
enum CommitmentPolicy {
    ESDK_FORBID_ENCRYPT_ALLOW_DECRYPT
    ESDK_REQUIRE_ENCRYPT_ALLOW_DECRYPT
    ESDK_REQUIRE_ENCRYPT_REQUIRE_DECRYPT
}

/// ESDK algorithm suite identifiers.
enum AlgorithmSuiteId {
    ALG_AES_128_GCM_IV12_TAG16_NO_KDF
    ALG_AES_192_GCM_IV12_TAG16_NO_KDF
    ALG_AES_256_GCM_IV12_TAG16_NO_KDF
    ALG_AES_128_GCM_IV12_TAG16_HKDF_SHA256
    ALG_AES_192_GCM_IV12_TAG16_HKDF_SHA256
    ALG_AES_256_GCM_IV12_TAG16_HKDF_SHA256
    ALG_AES_128_GCM_IV12_TAG16_HKDF_SHA256_ECDSA_P256
    ALG_AES_192_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384
    ALG_AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384
    ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY
    ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384
}

// ===========================================================================
// Resource handles
// ===========================================================================

/// An opaque handle to a server-side keyring or CMM.
@length(min: 1)
string ResourceId

// ===========================================================================
// CreateRawAesKeyring shapes
// ===========================================================================

@input
structure CreateRawAesKeyringRequest {
    /// Key provider ID / namespace for produced EDKs.
    @required
    keyNamespace: String

    /// Key name serialized into produced EDKs' key provider info.
    @required
    keyName: String

    /// Raw AES wrapping key (16, 24, or 32 bytes).
    @required
    wrappingKey: Blob

    @required
    wrappingAlg: AesWrappingAlg
}

@output
structure CreateRawAesKeyringResponse {
    /// Handle referencing the registered keyring for subsequent operations.
    @required
    keyringId: ResourceId
}

// ===========================================================================
// CreateKeyStoreClient shapes
// ===========================================================================

/// The server builds the key store's DynamoDB and KMS clients itself, from the
/// ambient AWS credentials and the regions given here. The regions are explicit
/// so every server reaches the same endpoints regardless of its environment.
@input
structure CreateKeyStoreClientRequest {
    /// DynamoDB table holding the branch keys.
    @required
    ddbTableName: String

    /// Logical key store name bound into each branch key's encryption context.
    @required
    logicalKeyStoreName: String

    /// How the key store chooses the KMS key that unwraps a branch key.
    @required
    kmsConfiguration: KmsConfiguration

    /// Region of the key store's KMS client.
    @required
    kmsClientRegion: String

    /// Region of the key store's DynamoDB client.
    @required
    ddbClientRegion: String
}

/// Mirrors the key store's KMSConfiguration.
union KmsConfiguration {
    /// Use only this KMS key. An MRK ARN is treated as single-region: a branch
    /// key whose record names another region's replica is rejected.
    kmsKeyArn: String

    /// Use only this KMS key, matching a record that names any replica of the
    /// same multi-Region key.
    kmsMRKeyArn: String

    /// Use the KMS key ARN each branch key record names.
    discovery: Discovery

    /// Use the KMS key ARN each branch key record names, with an MRK ARN's
    /// region replaced by the given region.
    mrDiscovery: MRDiscovery
}

structure Discovery {}

structure MRDiscovery {
    @required
    region: String
}

@output
structure CreateKeyStoreClientResponse {
    /// Handle referencing the registered key store for subsequent operations.
    @required
    keyStoreId: ResourceId
}

// ===========================================================================
// CreateCryptographicMaterialsCache shapes
// ===========================================================================

/// The MPL's Default cache type.
@input
structure CreateCryptographicMaterialsCacheRequest {
    /// Maximum number of entries the cache holds.
    @required
    @range(min: 1)
    entryCapacity: Integer
}

@output
structure CreateCryptographicMaterialsCacheResponse {
    /// Handle referencing the registered cache.
    @required
    cacheId: ResourceId
}

// ===========================================================================
// CreateAwsKmsHierarchicalKeyring shapes
// ===========================================================================

/// Exactly one of branchKeyId and branchKeyIdSupplier is set for a valid
/// keyring; the request passes both, or neither, through to the MPL unchanged,
/// so the MPL's own validation answers with MPLClientError.
@input
structure CreateAwsKmsHierarchicalKeyringRequest {
    /// Handle of a previously-registered key store.
    @required
    keyStoreId: ResourceId

    /// A single branch key used for every request.
    branchKeyId: String

    /// Selects the branch key per request from the encryption context.
    branchKeyIdSupplier: StaticBranchKeyIdSupplier

    /// How long fetched branch key materials stay in the cache.
    @required
    ttl: Duration

    /// Handle of a previously-registered cache, used as the keyring's Shared
    /// cache. When absent the keyring creates its own default cache.
    cacheId: ResourceId

    /// Partition of a shared cache this keyring reads and writes. When absent
    /// the MPL generates a random one.
    partitionId: String
}

@output
structure CreateAwsKmsHierarchicalKeyringResponse {
    /// Handle referencing the registered keyring for subsequent operations.
    @required
    keyringId: ResourceId
}

/// A branch key id supplier described as data, because the MPL's supplier is a
/// callback that cannot cross the wire. The server implements the MPL's branch
/// key id supplier interface as: look up the encryption context value under
/// encryptionContextKey; if branchKeyIds maps that value, return the mapped
/// branch key id; otherwise fail, so the keyring operation fails with
/// MPLClientError.
structure StaticBranchKeyIdSupplier {
    @required
    encryptionContextKey: String

    /// Encryption context value to branch key id.
    @required
    branchKeyIds: BranchKeyIdMap
}

map BranchKeyIdMap {
    key: String
    value: String
}

// ===========================================================================
// CreateDefaultCmm shapes
// ===========================================================================

@input
structure CreateDefaultCmmRequest {
    /// Handle of a previously-registered keyring.
    @required
    keyringId: ResourceId
}

@output
structure CreateDefaultCmmResponse {
    /// Handle referencing the registered CMM for subsequent operations.
    @required
    cmmId: ResourceId
}

// ===========================================================================
// Materials
// ===========================================================================

/// Mirrors the MPL's EncryptionMaterials.
///
/// plaintextDataKey is an unwrapped data key travelling over the server's
/// loopback HTTP connection. That is what lets a test carry materials from one
/// server's OnEncrypt to another server's OnDecrypt. Test key material only.
structure EncryptionMaterials {
    @required
    algorithmSuiteId: AlgorithmSuiteId

    @required
    encryptionContext: EncryptionContextMap

    @required
    encryptedDataKeys: EncryptedDataKeyList

    @required
    requiredEncryptionContextKeys: EncryptionContextKeys

    plaintextDataKey: Blob

    signingKey: Blob

    symmetricSigningKeys: BlobList
}

/// Mirrors the MPL's DecryptionMaterials.
structure DecryptionMaterials {
    @required
    algorithmSuiteId: AlgorithmSuiteId

    @required
    encryptionContext: EncryptionContextMap

    @required
    requiredEncryptionContextKeys: EncryptionContextKeys

    plaintextDataKey: Blob

    verificationKey: Blob

    symmetricSigningKey: Blob
}

// ===========================================================================
// InitializeEncryptionMaterials / InitializeDecryptionMaterials shapes
// ===========================================================================

/// Signing keys are not accepted: the keyring-level operations are exercised
/// with non-signing suites only, where the materials carry no signing key.
@input
structure InitializeEncryptionMaterialsRequest {
    @required
    algorithmSuiteId: AlgorithmSuiteId

    @required
    encryptionContext: EncryptionContextMap

    @required
    requiredEncryptionContextKeys: EncryptionContextKeys
}

@output
structure InitializeEncryptionMaterialsResponse {
    @required
    materials: EncryptionMaterials
}

@input
structure InitializeDecryptionMaterialsRequest {
    @required
    algorithmSuiteId: AlgorithmSuiteId

    @required
    encryptionContext: EncryptionContextMap

    @required
    requiredEncryptionContextKeys: EncryptionContextKeys
}

@output
structure InitializeDecryptionMaterialsResponse {
    @required
    materials: DecryptionMaterials
}

// ===========================================================================
// OnEncrypt / OnDecrypt shapes
// ===========================================================================

@input
structure OnEncryptRequest {
    /// Handle of a previously-registered keyring.
    @required
    keyringId: ResourceId

    @required
    materials: EncryptionMaterials
}

@output
structure OnEncryptResponse {
    @required
    materials: EncryptionMaterials
}

/// The encrypted data keys are a separate input rather than read from the
/// materials, as in the MPL's keyring interface. A test passes the EDKs one
/// server's OnEncrypt produced to another server's OnDecrypt.
@input
structure OnDecryptRequest {
    /// Handle of a previously-registered keyring.
    @required
    keyringId: ResourceId

    @required
    materials: DecryptionMaterials

    @required
    encryptedDataKeys: EncryptedDataKeyList
}

@output
structure OnDecryptResponse {
    @required
    materials: DecryptionMaterials
}

// ===========================================================================
// GetEncryptionMaterials shapes
// ===========================================================================

@input
structure GetEncryptionMaterialsRequest {
    /// Handle of a previously-registered CMM.
    @required
    cmmId: ResourceId

    /// Customer-supplied encryption context (additional authenticated data).
    encryptionContext: EncryptionContextMap

    @required
    commitmentPolicy: CommitmentPolicy

    /// Optional explicit algorithm suite override.
    algorithmSuiteId: AlgorithmSuiteId

    /// Optional maximum plaintext length the returned materials are valid for.
    maxPlaintextLength: Long
}

@output
structure GetEncryptionMaterialsResponse {
    /// The algorithm suite selected by the CMM.
    @required
    algorithmSuiteId: AlgorithmSuiteId

    /// Encryption context (may have been augmented by the CMM).
    @required
    encryptionContext: EncryptionContextMap

    /// One or more encrypted data keys produced by the keyring.
    @required
    encryptedDataKeys: EncryptedDataKeyList

    /// The plaintext data key for encryption.
    @required
    plaintextDataKey: Blob

    /// ECDSA signing key (present when suite has asymmetric signing).
    signingKey: Blob

    /// Symmetric signing keys (present when suite has symmetric signing).
    symmetricSigningKeys: BlobList
}

// ===========================================================================
// DecryptMaterials shapes
// ===========================================================================

@input
structure DecryptMaterialsRequest {
    /// Handle of a previously-registered CMM.
    @required
    cmmId: ResourceId

    /// Algorithm suite advertised in the message header.
    @required
    algorithmSuiteId: AlgorithmSuiteId

    /// Encrypted data keys from the message header.
    @required
    encryptedDataKeys: EncryptedDataKeyList

    /// Encryption context from the message header.
    encryptionContext: EncryptionContextMap

    @required
    commitmentPolicy: CommitmentPolicy

    /// Optional reproduced encryption context for validation.
    reproducedEncryptionContext: EncryptionContextMap
}

@output
structure DecryptMaterialsResponse {
    /// The decrypted plaintext data key.
    @required
    plaintextDataKey: Blob

    /// Encryption context (may have been merged/validated by the CMM).
    @required
    encryptionContext: EncryptionContextMap

    /// ECDSA verification key (present when suite has asymmetric signing).
    verificationKey: Blob

    /// Symmetric signing key (present when suite has symmetric signing).
    symmetricSigningKey: Blob
}

// ===========================================================================
// Shared shapes
// ===========================================================================

/// A span of time: seconds plus a sub-second nanosecond part. A server whose
/// MPL takes whole seconds MUST answer a non-zero nanos with GenericServerError.
structure Duration {
    @required
    @range(min: 0)
    seconds: Long

    @required
    @range(min: 0, max: 999999999)
    nanos: Integer
}

/// A single encrypted data key.
structure EncryptedDataKey {
    @required
    keyProviderId: String

    @required
    keyProviderInfo: Blob

    @required
    ciphertext: Blob
}

/// String-to-string encryption context map.
map EncryptionContextMap {
    key: String
    value: String
}

/// Encryption context keys that must be supplied again on decrypt.
list EncryptionContextKeys {
    member: String
}

list EncryptedDataKeyList {
    member: EncryptedDataKey
}

list BlobList {
    member: Blob
}

// ===========================================================================
// Errors
// ===========================================================================

/// Framework-side failure (bad request, unknown operation, absent/unknown/
/// wrong-kind handle). Never used for a failure the MPL raised.
@error("client")
structure GenericServerError {
    @required
    message: String
}

/// A failure forwarded from the underlying Material Providers Library.
@error("client")
structure MPLClientError {
    @required
    message: String
}
