$version: "2.0"

namespace aws.cryptography.dbesdk.testserver

// The transport protocol is declared exactly once, at the service level.
// rpcv2Cbor mirrors what the ESDK TestServer uses.
use smithy.protocols#rpcv2Cbor

/// The DB-ESDK TestServer service. Three operations wrap the DBE Java
/// `DynamoDbItemEncryptor` — the lowest-level DBE API that operates on an
/// already-materialized DDB item (a `Map<String, AttributeValue>`) rather
/// than intercepting a full DDB request. This is the direct analog of the
/// ESDK's `Encrypt` / `Decrypt` blob operations, adapted for DBE's item-level
/// wire format (each attribute is encrypted individually according to its
/// CryptoAction; there is no whole-message envelope).
///
/// Streaming operations exist in the ESDK model for wire-contract completeness
/// but have no DBE analog — DBE encrypts a bounded item, not a byte stream.
/// If a future revision needs the DDB request-transform surface (PutItem /
/// GetItem / TransactWriteItems / …), it becomes additional operations here;
/// the item-level operations stay as the primitive.
@rpcv2Cbor
service DBESDKTestServer {
    version: "2026-08-10"
    operations: [
        CreateClient
        EncryptItem
        DecryptItem
        CreateTransformsClient
        PutItemInputTransform
        GetItemOutputTransform
    ]
    errors: [
        GenericServerError
        DBESDKClientError
    ]
}

// ===========================================================================
// Operations
// ===========================================================================

/// Construct and register exactly one configured DBE item encryptor, returning
/// a non-empty ClientId that later operations pass to reference the same
/// client. CreateClient is the only operation that does not take a ClientId.
operation CreateClient {
    input: CreateClientRequest
    output: CreateClientResponse
    errors: [
        GenericServerError
        DBESDKClientError
    ]
}

/// Encrypt one DDB item with the referenced DBE item encryptor. Fields
/// configured as ENCRYPT_AND_SIGN are encrypted and included in the item
/// signature; SIGN_ONLY fields are signed but stay in the clear;
/// SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT fields are signed, stay in the
/// clear, and are bound into the header's Encryption Context; DO_NOTHING
/// fields are passed through untouched.
operation EncryptItem {
    input: EncryptItemRequest
    output: EncryptItemResponse
    errors: [
        GenericServerError
        DBESDKClientError
    ]
}

/// Decrypt one DDB item with the referenced DBE item encryptor. Verifies the
/// item signature, decrypts encrypted attributes, and returns the plaintext
/// item.
operation DecryptItem {
    input: DecryptItemRequest
    output: DecryptItemResponse
    errors: [
        GenericServerError
        DBESDKClientError
    ]
}

/// Construct and register a DBE DDB-SDK transforms client bound to a single
/// physical table, returning a non-empty ClientId that the transform
/// operations pass to reference it. Distinct from CreateClient's item
/// encryptor: a transforms client wraps the DBE `DynamoDbEncryptionTransforms`
/// surface, built from a `DynamoDbTablesEncryptionConfig` (one table name → one
/// crypto config). The crypto config reuses `DBEClientConfig`; `tableName` is
/// the physical DDB table the wire PutItemInput/GetItemInput reference.
operation CreateTransformsClient {
    input: CreateTransformsClientRequest
    output: CreateTransformsClientResponse
    errors: [
        GenericServerError
        DBESDKClientError
    ]
}

/// Encrypt-before hook: transform a DynamoDB PutItem input, encrypting the item
/// according to the table's Crypto Actions before it would be written. The
/// item-level dual of EncryptItem, reached through the DDB SDK integration
/// surface rather than the item encryptor.
operation PutItemInputTransform {
    input: PutItemInputTransformRequest
    output: PutItemInputTransformResponse
    errors: [
        GenericServerError
        DBESDKClientError
    ]
}

/// Decrypt-after hook: transform a DynamoDB GetItem output, decrypting the
/// returned item. The item-level dual of DecryptItem, reached through the DDB
/// SDK integration surface. A GetItem output with no item (the key matched
/// nothing) passes through unchanged.
operation GetItemOutputTransform {
    input: GetItemOutputTransformRequest
    output: GetItemOutputTransformResponse
    errors: [
        GenericServerError
        DBESDKClientError
    ]
}

// ===========================================================================
// Operation request / response shapes
// ===========================================================================

@input
structure CreateClientRequest {
    /// The DBE item encryptor configuration to construct.
    @required
    config: DBEClientConfig
}

@output
structure CreateClientResponse {
    /// A non-empty, collision-resistant identifier referencing exactly one
    /// registered DBE item encryptor.
    @required
    clientId: ClientId
}

@input
structure EncryptItemRequest {
    @required
    clientId: ClientId

    /// The plaintext DDB item to encrypt.
    @required
    plaintextItem: DDBItem
}

@output
structure EncryptItemResponse {
    /// The encrypted DDB item (same attribute names; encrypted attributes are
    /// now `B` (binary) values; SIGN_ONLY, SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT,
    /// and DO_NOTHING attributes retain their original values).
    @required
    encryptedItem: DDBItem
}

@input
structure DecryptItemRequest {
    @required
    clientId: ClientId

    /// The encrypted DDB item to decrypt.
    @required
    encryptedItem: DDBItem
}

@output
structure DecryptItemResponse {
    /// The plaintext DDB item recovered from the encrypted item.
    @required
    plaintextItem: DDBItem
}

@input
structure CreateTransformsClientRequest {
    /// The crypto configuration for the table this transforms client is bound
    /// to. Reuses the item-encryptor config shape; the transforms client keys
    /// it under `tableName`.
    @required
    config: DBEClientConfig

    /// The physical DDB table name the transforms client is bound to. Wire
    /// PutItemInput / GetItemInput requests must reference this same name.
    @required
    tableName: String
}

@output
structure CreateTransformsClientResponse {
    /// A non-empty, collision-resistant identifier referencing exactly one
    /// registered transforms client.
    @required
    clientId: ClientId
}

@input
structure PutItemInputTransformRequest {
    @required
    clientId: ClientId

    /// The DynamoDB PutItem input to transform (encrypt-before).
    @required
    sdkInput: PutItemInput
}

@output
structure PutItemInputTransformResponse {
    /// The transformed PutItem input, whose item is now encrypted per the
    /// table's Crypto Actions (encrypted attributes are `B` binary values;
    /// SIGN_ONLY / SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT / DO_NOTHING
    /// attributes retain their original values, plus the `aws_dbe_head` and
    /// `aws_dbe_foot` attributes).
    @required
    transformedInput: PutItemInput
}

@input
structure GetItemOutputTransformRequest {
    @required
    clientId: ClientId

    /// The DynamoDB GetItem output to transform (decrypt-after).
    @required
    sdkOutput: GetItemOutput

    /// The original DynamoDB GetItem input that produced `sdkOutput`.
    @required
    originalInput: GetItemInput
}

@output
structure GetItemOutputTransformResponse {
    /// The transformed GetItem output, whose item (when present) is now
    /// decrypted.
    @required
    transformedOutput: GetItemOutput
}

// ===========================================================================
// Minimal DynamoDB wire shapes for the transform operations. These carry only
// the fields the encrypt-before / decrypt-after round-trip needs; each server
// maps them onto the real AWS SDK DynamoDB request/response types the DBE
// transforms API consumes.
// ===========================================================================

/// A DynamoDB PutItem input: the target table and the item to write.
structure PutItemInput {
    @required
    tableName: String

    @required
    item: DDBItem
}

/// A DynamoDB GetItem input: the target table and the primary key to read.
structure GetItemInput {
    @required
    tableName: String

    @required
    key: DDBItem
}

/// A DynamoDB GetItem output: the returned item, absent when the key matched
/// no item.
structure GetItemOutput {
    item: DDBItem
}

// ===========================================================================
// Modeled errors
// ===========================================================================

/// TestServer-framework failures: bad clientId, malformed request, unsupported
/// configuration variant, any non-modeled exception caught by the operation
/// wrapper.
@error("client")
structure GenericServerError {
    @required
    message: String
}

/// Exception forwarded from the underlying DBE library. Message is the DBE
/// exception's message, unmodified.
@error("client")
structure DBESDKClientError {
    @required
    message: String
}

// ===========================================================================
// Scalar / collection primitives
// ===========================================================================

/// A non-empty, UUID-format identifier returned by CreateClient.
string ClientId

/// A DDB item: attribute name → AttributeValue.
map DDBItem {
    key: String
    value: AttributeValue
}

/// DynamoDB AttributeValue, modeled as a tagged union via optional members —
/// exactly one member is expected to be set at runtime. Matches the DDB Data
/// Plane AttributeValue shape.
///
/// Scalars (S / N / B / BOOL / NULL), typed sets (SS / NS / BS), and the
/// recursive collection types (L / M) are all modeled. L and M reference
/// AttributeValue recursively, so arbitrarily nested items round-trip.
structure AttributeValue {
    /// String value.
    S: String

    /// Number value. DDB carries N as a string to preserve precision.
    N: String

    /// Binary value.
    B: Blob

    /// Boolean value.
    BOOL: Boolean

    /// Null attribute. When present, the boolean is always `true`.
    NULL: Boolean

    /// String set. DDB sets are unordered and carry no duplicates.
    SS: StringSetAttributeValue

    /// Number set. Each element is a string, matching N.
    NS: NumberSetAttributeValue

    /// Binary set.
    BS: BinarySetAttributeValue

    /// List of AttributeValues (ordered, heterogeneous). Recursive.
    L: ListAttributeValue

    /// Map of String to AttributeValue. Recursive.
    M: MapAttributeValue
}

/// String set member type for AttributeValue.SS.
list StringSetAttributeValue {
    member: String
}

/// Number set member type for AttributeValue.NS.
list NumberSetAttributeValue {
    member: String
}

/// Binary set member type for AttributeValue.BS.
list BinarySetAttributeValue {
    member: Blob
}

/// List member type for AttributeValue.L (recursive).
list ListAttributeValue {
    member: AttributeValue
}

/// Map member type for AttributeValue.M (recursive).
map MapAttributeValue {
    key: String
    value: AttributeValue
}

// ===========================================================================
// DBE client configuration (mirrors DynamoDbItemEncryptorConfig at the lowest
// faithful API layer). Runtime-only members (live AWS SDK clients, MPL
// providers) are constructed server-side from the serializable configuration
// below; only serializable configuration is on the wire.
//
// The DBE config accepts EITHER a keyring OR a CMM (exactly one), matching
// the DBE builder's own constraint. Both slots are modeled as optional
// members of DBEClientConfig; the "exactly one variant set" invariant is
// enforced server-side.
// ===========================================================================
structure DBEClientConfig {
    /// A stable logical name for the (real or virtual) DDB table this
    /// encryptor is bound to. Bound into the AAD, so two encryptors with
    /// different logical names cannot decrypt each other's items.
    @required
    logicalTableName: String

    /// The partition attribute's name. Its CryptoAction must be SIGN_ONLY
    /// (v1 configuration) or SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT
    /// (v2 configuration — implied when any attribute uses that action).
    @required
    partitionKeyName: String

    /// The sort attribute's name (optional — some tables have none). If
    /// present, its CryptoAction must be SIGN_ONLY (v1 configuration) or
    /// SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT (v2 configuration — implied
    /// when any attribute uses that action).
    sortKeyName: String

    /// Per-attribute action taken during encrypt. Every attribute that will
    /// ever appear on the item must have an entry.
    @required
    attributeActionsOnEncrypt: AttributeActionsOnEncrypt

    /// Prefix marking attributes that are NOT part of the signature scope
    /// (typically ":"). Preferred over explicit `allowedUnsignedAttributes`
    /// because it does not require a rewriter deploy to add new
    /// unauthenticated attributes.
    allowedUnsignedAttributePrefix: String

    /// Explicit list of attribute names to leave out of the signature scope.
    /// Once populated it is unsafe to remove names, as older items may still
    /// carry them.
    allowedUnsignedAttributes: AttributeNameList

    /// Optional algorithm-suite override. Defaults to the DBE default when
    /// omitted.
    algorithmSuiteId: DBEAlgorithmSuiteId

    /// The keyring backing this client (mutually exclusive with `cmm`).
    keyring: Keyring

    /// The cryptographic-materials manager backing this client (mutually
    /// exclusive with `keyring`).
    cmm: CryptographicMaterialsManager
}

map AttributeActionsOnEncrypt {
    key: String
    value: CryptoAction
}

list AttributeNameList {
    member: String
}

enum CryptoAction {
    /// Attribute is encrypted AND included in the signature scope.
    ENCRYPT_AND_SIGN

    /// Attribute is NOT encrypted but IS included in the signature scope.
    SIGN_ONLY

    /// Attribute is NOT encrypted, IS included in the signature scope, and
    /// its value is bound into the header's Encryption Context as an
    /// `aws-crypto-attr.NAME` entry. Any attribute with this action implies
    /// a v2 Configuration Version; v2 additionally requires the partition
    /// (and, if present, sort) key attribute to use this same action.
    SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT

    /// Attribute is NOT encrypted and NOT signed.
    DO_NOTHING
}

/// DBE algorithm suite identifiers (as defined by MPL). The suite governs
/// the item's per-attribute AES-GCM parameters and the signature scheme.
enum DBEAlgorithmSuiteId {
    /// AES-256-GCM + HKDF-SHA-512 + key commitment + HMAC-SHA-384 signature.
    /// Symmetric signatures — no per-item ECDSA overhead.
    ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY_SYMSIG_HMAC_SHA384

    /// Same as above, additionally signed with ECDSA-P384. The DBE default.
    ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384_SYMSIG_HMAC_SHA384
}

// ===========================================================================
// Cryptographic Materials Managers (polymorphic; tagged union via optional
// members). Exactly one variant is expected to be set at runtime.
//
// The Default and RequiredEncryptionContext variants are supported by every
// DBE keyring. Caching wraps another CMM — a recursive variant.
// ===========================================================================
structure CryptographicMaterialsManager {
    /// Default CMM wrapping a keyring.
    Default: DefaultCmmConfig

    /// CMM that enforces a set of required encryption-context keys.
    RequiredEncryptionContext: RequiredEncryptionContextCmmConfig

    /// Caching CMM wrapping another CMM (recursion point).
    Caching: CachingCmmConfig
}

structure DefaultCmmConfig {
    @required
    keyring: Keyring
}

structure RequiredEncryptionContextCmmConfig {
    @required
    underlyingCMM: CryptographicMaterialsManager

    @required
    requiredEncryptionContextKeys: EncryptionContextKeys
}

structure CachingCmmConfig {
    @required
    underlyingCMM: CryptographicMaterialsManager

    @required
    cacheLimitTtlSeconds: Integer

    partitionId: String
    limitBytes: Long
    limitMessages: Long
}

list EncryptionContextKeys {
    member: String
}

// ===========================================================================
// Keyrings (polymorphic; tagged union via optional members). Same MPL keyring
// surface as the ESDK model — DBE reuses these unchanged. Exactly one variant
// is expected to be set at runtime. The Multi variant references Keyring
// recursively.
// ===========================================================================
structure Keyring {
    AwsKms: AwsKmsKeyringConfig
    AwsKmsMrk: AwsKmsMrkKeyringConfig
    AwsKmsMultiKeyring: AwsKmsMultiKeyringConfig
    AwsKmsMrkMultiKeyring: AwsKmsMrkMultiKeyringConfig
    AwsKmsDiscovery: AwsKmsDiscoveryKeyringConfig
    AwsKmsMrkDiscovery: AwsKmsMrkDiscoveryKeyringConfig
    AwsKmsRsa: AwsKmsRsaKeyringConfig
    RawAes: RawAesKeyringConfig
    RawRsa: RawRsaKeyringConfig
    AwsKmsHierarchical: AwsKmsHierarchicalKeyringConfig
    Multi: MultiKeyringConfig
}

structure AwsKmsKeyringConfig {
    @required
    kmsKeyId: String

    grantTokens: GrantTokenList
}

structure AwsKmsMrkKeyringConfig {
    @required
    kmsKeyId: String

    grantTokens: GrantTokenList
}

structure AwsKmsMultiKeyringConfig {
    generator: String
    kmsKeyIds: KmsKeyIdList
    grantTokens: GrantTokenList
}

structure AwsKmsMrkMultiKeyringConfig {
    generator: String
    kmsKeyIds: KmsKeyIdList
    grantTokens: GrantTokenList
}

structure AwsKmsDiscoveryKeyringConfig {
    discoveryFilter: DiscoveryFilter
    grantTokens: GrantTokenList
}

structure AwsKmsMrkDiscoveryKeyringConfig {
    @required
    region: String

    discoveryFilter: DiscoveryFilter

    grantTokens: GrantTokenList
}

structure AwsKmsRsaKeyringConfig {
    @required
    kmsKeyId: String

    publicKey: Blob

    encryptionAlgorithm: KmsRsaEncryptionAlgorithm

    grantTokens: GrantTokenList
}

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

structure RawRsaKeyringConfig {
    @required
    keyNamespace: String

    @required
    keyName: String

    @required
    paddingScheme: PaddingScheme

    publicKey: Blob
    privateKey: Blob
}

enum PaddingScheme {
    PKCS1
    OAEP_SHA1_MGF1
    OAEP_SHA256_MGF1
    OAEP_SHA384_MGF1
    OAEP_SHA512_MGF1
}

/// AWS KMS Hierarchical keyring — branch keys persisted in a DynamoDB key
/// store, each wrapped by a KMS key. Common to ESDK and DBE.
structure AwsKmsHierarchicalKeyringConfig {
    @required
    branchKeyId: String

    @required
    keyStoreTableName: String

    @required
    logicalKeyStoreName: String

    @required
    kmsKeyArn: String

    @required
    ttlSeconds: Integer
}

/// Multi-keyring combining other keyrings. At least one of `generator` or
/// `childKeyrings` must be defined. Recursive via childKeyrings.
structure MultiKeyringConfig {
    generator: Keyring

    @required
    childKeyrings: KeyringList
}

list KeyringList {
    member: Keyring
}
