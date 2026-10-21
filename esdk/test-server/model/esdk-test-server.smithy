$version: "2.0"

namespace aws.cryptography.esdk.testserver

// The transport protocol is declared exactly once, here at the service level
// (Requirement 1.4). rpcv2Cbor is a plain Smithy protocol and uses no
// disallowed traits (Requirement 1.2).
use smithy.protocols#rpcv2Cbor

/// The single ESDK TestServer service. One hand-written Smithy 2.0 model is the
/// single source of truth for the wire contract shared by the one generated Java
/// Test_Client and every Language_Server, generated or hand-implemented
/// (Requirements 1.1, 1.9).
///
/// The protocol is declared once, at the service level (Requirement 1.4). Both
/// modeled errors are declared on the service so they apply to every operation
/// (Requirement 5.4); each operation also declares them explicitly below.
@rpcv2Cbor
service ESDKTestServer {
    version: "2026-06-30"
    operations: [
        CreateClient
        Encrypt
        EncryptStream
        Decrypt
        DecryptStream
    ]
    errors: [
        GenericServerError
        ESDKClientError
    ]
}

// ===========================================================================
// Operations
// ===========================================================================
/// Construct and register exactly one configured ESDK_Client, returning a
/// non-empty ClientId that later operations pass to reference the same client
/// (Requirements 3.1, 3.5). CreateClient is the only operation that does not
/// take a ClientId.
operation CreateClient {
    input: CreateClientRequest
    output: CreateClientResponse
    errors: [
        GenericServerError
        ESDKClientError
    ]
}

/// Blob variant of encrypt: encrypt an in-memory plaintext blob with the
/// referenced ESDK_Client and return the resulting ciphertext blob
/// (Requirements 4.1, 4.2).
operation Encrypt {
    input: EncryptRequest
    output: EncryptResponse
    errors: [
        GenericServerError
        ESDKClientError
    ]
}

/// Stream variant of encrypt. Modeled for wire-contract completeness
/// (Requirement 4.1). Streaming-capable servers process it (Requirement 4.5);
/// non-streaming servers return a GenericServerError (Requirement 4.7).
operation EncryptStream {
    input: EncryptStreamRequest
    output: EncryptStreamResponse
    errors: [
        GenericServerError
        ESDKClientError
    ]
}

/// Blob variant of decrypt: decrypt an in-memory ciphertext blob with the
/// referenced ESDK_Client and return the resulting plaintext blob
/// (Requirements 4.1, 4.3).
operation Decrypt {
    input: DecryptRequest
    output: DecryptResponse
    errors: [
        GenericServerError
        ESDKClientError
    ]
}

/// Stream variant of decrypt. Modeled for wire-contract completeness
/// (Requirement 4.1). Streaming-capable servers process it (Requirement 4.6);
/// non-streaming servers return a GenericServerError (Requirement 4.7).
operation DecryptStream {
    input: DecryptStreamRequest
    output: DecryptStreamResponse
    errors: [
        GenericServerError
        ESDKClientError
    ]
}

// ===========================================================================
// Operation request / response shapes
// ===========================================================================
@input
structure CreateClientRequest {
    /// The ESDK client configuration to construct, modeled at the lowest
    /// faithful ESDK API layer (Requirement 2.1).
    @required
    config: ESDKClientConfig
}

@output
structure CreateClientResponse {
    /// A non-empty, collision-resistant identifier (UUID-format recommended)
    /// referencing exactly one registered ESDK_Client (Requirements 3.1, 3.2).
    @required
    clientId: ClientId
}

@input
structure EncryptRequest {
    /// References the configured ESDK_Client to use (Requirement 3.8).
    @required
    clientId: ClientId

    /// The plaintext to encrypt, passed as a single in-memory byte blob
    /// (Blob_Variant, Requirement 4.2).
    @required
    plaintext: Blob

    /// Optional encryption context (additional authenticated data).
    encryptionContext: EncryptionContext

    /// Optional explicit algorithm suite override.
    algorithmSuiteId: ESDKAlgorithmSuiteId

    /// Optional framing length in bytes.
    frameLength: Long
}

@output
structure EncryptResponse {
    @required
    ciphertext: Blob
}

@input
structure DecryptRequest {
    @required
    clientId: ClientId

    /// The ciphertext to decrypt, passed as a single in-memory byte blob
    /// (Blob_Variant, Requirement 4.3).
    @required
    ciphertext: Blob

    /// Optional encryption context required to be present on decrypt.
    encryptionContext: EncryptionContext
}

@output
structure DecryptResponse {
    @required
    plaintext: Blob

    /// The encryption context the decryptor authenticated from the message
    /// (spec/client-apis/decrypt.md). Optional: a Language_Server that does not
    /// expose its decrypt result omits it.
    encryptionContext: EncryptionContext

    /// The algorithm suite the decryptor determined from the message header.
    /// Optional for the same reason.
    algorithmSuiteId: ESDKAlgorithmSuiteId
}

@input
structure EncryptStreamRequest {
    @required
    clientId: ClientId

    /// The plaintext for the Stream_Variant of encrypt. It is carried as a plain
    /// Blob on the wire (NOT a Smithy `@streaming` member) because the rpcv2-CBOR
    /// protocol this service declares does not transmit `@streaming` members with
    /// stock smithy-java 1.4.0. The Stream_Variant is distinguished from the
    /// Blob_Variant by the Language_Server driving the ESDK streaming API
    /// internally, not by the wire encoding (Requirements 4.1, 4.5).
    @required
    plaintext: Blob

    encryptionContext: EncryptionContext

    algorithmSuiteId: ESDKAlgorithmSuiteId

    frameLength: Long

    /// Optional plaintext length bound: encrypt MUST NOT encrypt a plaintext longer
    /// than this value (spec/client-apis/encrypt.md#plaintext-length-bound).
    plaintextLengthBound: Long
}

@output
structure EncryptStreamResponse {
    /// Ciphertext produced by the server driving the ESDK streaming encrypt API;
    /// carried as a plain Blob on the wire (Requirements 4.1, 4.5).
    @required
    ciphertext: Blob
}

@input
structure DecryptStreamRequest {
    @required
    clientId: ClientId

    /// The ciphertext for the Stream_Variant of decrypt. It is carried as a plain
    /// Blob on the wire (NOT a Smithy `@streaming` member) because the rpcv2-CBOR
    /// protocol this service declares does not transmit `@streaming` members with
    /// stock smithy-java 1.4.0. The Stream_Variant is distinguished from the
    /// Blob_Variant by the Language_Server driving the ESDK streaming API
    /// internally, not by the wire encoding (Requirements 4.1, 4.6).
    @required
    ciphertext: Blob

    encryptionContext: EncryptionContext
}

@output
structure DecryptStreamResponse {
    /// Plaintext produced by the server driving the ESDK streaming decrypt API;
    /// carried as a plain Blob on the wire (Requirements 4.1, 4.6).
    @required
    plaintext: Blob

    /// The encryption context the decryptor authenticated from the message
    /// (spec/client-apis/decrypt.md). Optional: a Language_Server that does not
    /// expose its decrypt result omits it.
    encryptionContext: EncryptionContext

    /// The algorithm suite the decryptor determined from the message header.
    /// Optional for the same reason.
    algorithmSuiteId: ESDKAlgorithmSuiteId
}

// ===========================================================================
// Two modeled error shapes (Requirement 5.1), each declared on every operation
// (Requirement 5.4), each carrying a required message member (Requirements
// 5.2, 5.3).
// ===========================================================================
/// Returned for failures originating in the TestServer framework itself:
/// client-construction failure (Requirement 3.6), missing/empty/unknown
/// ClientId (Requirement 3.9), stream variant on a non-streaming server
/// (Requirement 4.7), and any non-modeled exception caught by the operation
/// wrapper (Requirement 6.2).
@error("client")
structure GenericServerError {
    @required
    message: String
}

/// Returned for exceptions forwarded from the underlying ESDK_Client. Its
/// message is the ESDK exception's message, unmodified (Requirement 5.6).
@error("client")
structure ESDKClientError {
    @required
    message: String
}

// ===========================================================================
// Core scalar / collection shapes
// ===========================================================================
/// A non-empty, UUID-format (or equivalent collision-resistant) identifier
/// returned by CreateClient (Requirements 3.1, 3.2).
string ClientId

/// Encryption context: a string-to-string map (additional authenticated data).
map EncryptionContext {
    key: String
    value: String
}

// The Stream_Variant operations carry their payloads as the built-in `Blob`
// shape (see EncryptStreamRequest/DecryptStreamRequest and their responses).
// There is deliberately NO `@streaming` blob shape: stock smithy-java 1.4.0 does
// not transmit `@streaming` members over the rpcv2-CBOR protocol this service
// declares, so the streaming semantics live entirely server-side — the
// Language_Server wraps the received blob in a stream, drives the ESDK streaming
// encrypt/decrypt API, and collects the streamed output back into a blob
// (Requirement 4.1).

// ===========================================================================
// ESDK client configuration (mirrors the real ESDK config at the lowest
// faithful API layer, Requirement 2.1).
//
// ESDK polymorphic members (keyrings, cryptographic materials managers) are
// modeled as a structure containing exactly one optional member per variant —
// the "tagged union via optional members" pattern (Requirement 2.2). The
// "exactly one variant member set" invariant is enforced at runtime by the
// Language_Server, not by the type system (Requirements 2.3, 2.4). Recursive
// variants reference the same structure to any nesting depth (Requirement 2.5).
//
// Note: runtime-only members that cannot cross the wire (for example a live AWS
// KMS SDK client instance) are constructed server-side from the serializable
// configuration below; only serializable configuration is modeled.
// ===========================================================================
structure ESDKClientConfig {
    /// Coordinates key commitment between encrypt and decrypt
    /// (commitment-policy.md).
    @required
    commitmentPolicy: ESDKCommitmentPolicy

    /// Optional cap on the number of encrypted data keys.
    maxEncryptedDataKeys: Long

    /// The cryptographic materials manager backing this client. Polymorphic:
    /// modeled as a tagged union via optional members (Requirement 2.2).
    @required
    cmm: CryptographicMaterialsManager
}

enum ESDKCommitmentPolicy {
    FORBID_ENCRYPT_ALLOW_DECRYPT
    REQUIRE_ENCRYPT_ALLOW_DECRYPT
    REQUIRE_ENCRYPT_REQUIRE_DECRYPT
}

enum ESDKAlgorithmSuiteId {
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

// ---------------------------------------------------------------------------
// Cryptographic Materials Managers (polymorphic, tagged union via optional
// members). Exactly one member is expected to be set at runtime (Requirements
// 2.2, 2.3, 2.4).
// ---------------------------------------------------------------------------
structure CryptographicMaterialsManager {
    /// Default CMM wrapping a keyring (default-cmm.md).
    Default: DefaultCmmConfig

    /// CMM that enforces a set of required encryption context keys
    /// (required-encryption-context-cmm.md).
    RequiredEncryptionContext: RequiredEncryptionContextCmmConfig

    /// Caching CMM wrapping another CMM — a recursive variant
    /// (caching-cmm.md, Requirement 2.5).
    Caching: CachingCmmConfig
}

/// Default CMM: built-in CMM that wraps a keyring (default-cmm.md).
structure DefaultCmmConfig {
    @required
    keyring: Keyring
}

/// Required-encryption-context CMM: wraps another CMM and pins required
/// encryption context keys. Recursive via underlyingCMM (Requirement 2.5).
structure RequiredEncryptionContextCmmConfig {
    @required
    underlyingCMM: CryptographicMaterialsManager

    @required
    requiredEncryptionContextKeys: EncryptionContextKeys
}

/// Caching CMM: wraps another CMM (recursive, Requirement 2.5) and caches its
/// results (caching-cmm.md).
structure CachingCmmConfig {
    /// The wrapped CMM whose results are cached — recursion point.
    @required
    underlyingCMM: CryptographicMaterialsManager

    /// Maximum time-to-live, in seconds, for a cached data key (> 0).
    @required
    cacheLimitTtlSeconds: Integer

    /// Optional partition id to share or isolate cache entries.
    partitionId: String

    /// Optional cap on bytes encrypted under a single data key.
    limitBytes: Long

    /// Optional cap on messages encrypted under a single data key.
    limitMessages: Long
}

list EncryptionContextKeys {
    member: String
}

// ---------------------------------------------------------------------------
// Keyrings (polymorphic, tagged union via optional members). Exactly one
// member is expected to be set at runtime (Requirements 2.2, 2.3, 2.4). The
// Multi variant references Keyring recursively to any depth (Requirement 2.5).
// ---------------------------------------------------------------------------
structure Keyring {
    /// AWS KMS keyring (aws-kms-keyring.md).
    AwsKms: AwsKmsKeyringConfig

    /// AWS KMS MRK-aware keyring (aws-kms-mrk-keyring.md).
    AwsKmsMrk: AwsKmsMrkKeyringConfig

    /// AWS KMS multi-keyring (aws-kms-multi-keyrings.md).
    AwsKmsMultiKeyring: AwsKmsMultiKeyringConfig

    /// AWS KMS MRK-aware multi-keyring (aws-kms-mrk-multi-keyrings.md).
    AwsKmsMrkMultiKeyring: AwsKmsMrkMultiKeyringConfig

    /// AWS KMS discovery keyring (aws-kms-discovery-keyring.md).
    AwsKmsDiscovery: AwsKmsDiscoveryKeyringConfig

    /// AWS KMS MRK-aware discovery keyring: decrypt-only discovery normalized to
    /// a region so it can decrypt multi-region keys written in another region
    /// (aws-kms-mrk-discovery-keyring.md).
    AwsKmsMrkDiscovery: AwsKmsMrkDiscoveryKeyringConfig

    /// AWS KMS RSA keyring (aws-kms-rsa-keyring.md).
    AwsKmsRsa: AwsKmsRsaKeyringConfig

    /// Raw AES keyring (raw-aes-keyring.md).
    RawAes: RawAesKeyringConfig

    /// Raw RSA keyring (raw-rsa-keyring.md).
    RawRsa: RawRsaKeyringConfig

    /// AWS KMS Hierarchical keyring: branch keys in a DynamoDB key store wrapped
    /// by a KMS key (aws-kms-hierarchical-keyring.md).
    AwsKmsHierarchical: AwsKmsHierarchicalKeyringConfig

    /// Multi-keyring combining other keyrings — a recursive variant
    /// (multi-keyring.md, Requirement 2.5).
    Multi: MultiKeyringConfig
}

/// AWS KMS keyring. The live KMS SDK client is constructed server-side; only
/// serializable configuration is modeled here.
structure AwsKmsKeyringConfig {
    @required
    kmsKeyId: String

    grantTokens: GrantTokenList
}

/// AWS KMS MRK-aware keyring.
structure AwsKmsMrkKeyringConfig {
    @required
    kmsKeyId: String

    grantTokens: GrantTokenList
}

/// AWS KMS multi-keyring with an optional generator and child key identifiers
/// (aws-kms-multi-keyrings.md).
structure AwsKmsMultiKeyringConfig {
    generator: String
    kmsKeyIds: KmsKeyIdList
    grantTokens: GrantTokenList
}

/// AWS KMS MRK-aware multi-keyring with an optional MRK generator and child MRK
/// key identifiers (aws-kms-mrk-multi-keyrings.md). Same shape as
/// AwsKmsMultiKeyringConfig; the MRK-aware form matches multi-region keys across
/// regions on decrypt.
structure AwsKmsMrkMultiKeyringConfig {
    generator: String
    kmsKeyIds: KmsKeyIdList
    grantTokens: GrantTokenList
}

/// AWS KMS discovery keyring (aws-kms-discovery-keyring.md).
structure AwsKmsDiscoveryKeyringConfig {
    discoveryFilter: DiscoveryFilter
    grantTokens: GrantTokenList
}

/// AWS KMS MRK-aware discovery keyring (aws-kms-mrk-discovery-keyring.md). A
/// decrypt-only discovery keyring normalized to a single region, so it can
/// decrypt a multi-region key written in another region.
structure AwsKmsMrkDiscoveryKeyringConfig {
    @required
    region: String

    discoveryFilter: DiscoveryFilter

    grantTokens: GrantTokenList
}

/// AWS KMS RSA keyring (aws-kms-rsa-keyring.md).
structure AwsKmsRsaKeyringConfig {
    @required
    kmsKeyId: String

    publicKey: Blob

    encryptionAlgorithm: KmsRsaEncryptionAlgorithm

    grantTokens: GrantTokenList
}

/// Optional account/partition scoping for discovery keyrings.
structure DiscoveryFilter {
    @required
    partition: String

    @required
    accountIds: AccountIdList
}

list AccountIdList {
    member: String
}

list KmsKeyIdList {
    member: String
}

list GrantTokenList {
    member: String
}

enum KmsRsaEncryptionAlgorithm {
    RSAES_OAEP_SHA_1
    RSAES_OAEP_SHA_256
}

/// Raw AES keyring. The wrapping key length must match the wrapping algorithm
/// (raw-aes-keyring.md).
structure RawAesKeyringConfig {
    @required
    keyNamespace: String

    @required
    keyName: String

    @required
    wrappingKey: Blob

    @required
    wrappingAlg: AesWrappingAlg
}

enum AesWrappingAlg {
    ALG_AES128_GCM_IV12_TAG16
    ALG_AES192_GCM_IV12_TAG16
    ALG_AES256_GCM_IV12_TAG16
}

/// Raw RSA keyring. Provide a public key (for encrypt), a private key (for
/// decrypt), or both (raw-rsa-keyring.md).
structure RawRsaKeyringConfig {
    @required
    keyNamespace: String

    @required
    keyName: String

    @required
    paddingScheme: PaddingScheme

    /// PEM-encoded public key (X.509 SubjectPublicKeyInfo).
    publicKey: Blob

    /// PEM-encoded private key (PKCS#8 PrivateKeyInfo).
    privateKey: Blob
}

enum PaddingScheme {
    PKCS1
    OAEP_SHA1_MGF1
    OAEP_SHA256_MGF1
    OAEP_SHA384_MGF1
    OAEP_SHA512_MGF1
}

/// AWS KMS Hierarchical keyring configuration. Only serializable configuration
/// is modeled; the DynamoDB and KMS clients are constructed server-side from the
/// ambient AWS configuration. The branch key material is persisted in the named
/// DynamoDB key store and wrapped by the referenced KMS key.
structure AwsKmsHierarchicalKeyringConfig {
    /// The branch key id whose material wraps and unwraps data keys.
    @required
    branchKeyId: String

    /// The DynamoDB table name backing the branch key store.
    @required
    keyStoreTableName: String

    /// The logical key store name bound into the key store's authenticated data.
    @required
    logicalKeyStoreName: String

    /// The KMS key ARN protecting the branch keys.
    @required
    kmsKeyArn: String

    /// How long, in seconds, branch key material may be cached before re-fetch.
    @required
    ttlSeconds: Integer
}

/// Multi-keyring combining other keyrings. At least one of generator or
/// childKeyrings must be defined (multi-keyring.md). childKeyrings references
/// Keyring recursively (Requirement 2.5).
structure MultiKeyringConfig {
    /// Optional generator keyring (recursion point).
    generator: Keyring

    /// Child keyrings (recursion point through a list).
    @required
    childKeyrings: KeyringList
}

list KeyringList {
    member: Keyring
}
