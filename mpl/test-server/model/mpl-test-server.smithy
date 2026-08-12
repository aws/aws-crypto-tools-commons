$version: "2.0"

namespace aws.cryptography.mpl.testserver

use smithy.protocols#rpcv2Cbor

/// The MPL TestServer service. A single hand-written Smithy 2.0 model
/// is the source of truth for the wire contract shared by every Language_Server.
///
/// Unlike the ESDK TestServer (which exercises encrypt/decrypt end-to-end),
/// the MPL TestServer exercises the Material Providers Library primitives:
/// keyring construction, CMM construction, and materials retrieval.
@rpcv2Cbor
service MPLTestServer {
    version: "2026-08-12"
    operations: [
        CreateRawAesKeyring
        CreateDefaultCmm
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

/// Construct and register a Default CMM wrapping a previously-registered
/// keyring, returning its handle.
operation CreateDefaultCmm {
    input: CreateDefaultCmmRequest
    output: CreateDefaultCmmResponse
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

/// Commitment policy (ESDK format only in this version).
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
    keyringId: String
}

// ===========================================================================
// CreateDefaultCmm shapes
// ===========================================================================

@input
structure CreateDefaultCmmRequest {
    /// Handle of a previously-registered keyring.
    @required
    keyringId: String
}

@output
structure CreateDefaultCmmResponse {
    /// Handle referencing the registered CMM for subsequent operations.
    @required
    cmmId: String
}

// ===========================================================================
// GetEncryptionMaterials shapes
// ===========================================================================

@input
structure GetEncryptionMaterialsRequest {
    /// Handle of a previously-registered CMM.
    @required
    cmmId: String

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
    cmmId: String

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

list EncryptedDataKeyList {
    member: EncryptedDataKey
}

list BlobList {
    member: Blob
}

// ===========================================================================
// Errors
// ===========================================================================

/// Framework-side failure (bad request, unknown operation, unknown handle).
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
