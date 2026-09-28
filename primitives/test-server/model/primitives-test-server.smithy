$version: "2.0"

namespace aws.cryptography.primitives.testserver

use smithy.protocols#rpcv2Cbor

/// The Primitives TestServer service. A single hand-written Smithy 2.0 model
/// is the source of truth for the wire contract shared by every Language_Server.
///
/// The protocol is declared once at the service level. Both modeled errors are
/// declared on the service so they apply to every operation.
@rpcv2Cbor
service PrimitivesTestServer {
    version: "2026-08-12"
    operations: [
        AesEncrypt
        AesDecrypt
        GenerateRandomBytes
        Digest
        Hmac
        Hkdf
        KbkdfCtrHmac
        EcdsaGenerateKeyPair
        EcdsaSign
        EcdsaVerify
    ]
    errors: [
        GenericServerError
        PrimitivesError
    ]
}

// ===========================================================================
// Operations
// ===========================================================================

/// Encrypt a plaintext message with AES-GCM.
operation AesEncrypt {
    input: AesEncryptRequest
    output: AesEncryptResponse
    errors: [GenericServerError, PrimitivesError]
}

/// Decrypt a ciphertext with AES-GCM.
operation AesDecrypt {
    input: AesDecryptRequest
    output: AesDecryptResponse
    errors: [GenericServerError, PrimitivesError]
}

/// Generate cryptographically secure random bytes.
operation GenerateRandomBytes {
    input: GenerateRandomBytesRequest
    output: GenerateRandomBytesResponse
    errors: [GenericServerError, PrimitivesError]
}

/// Compute a cryptographic digest (hash).
operation Digest {
    input: DigestRequest
    output: DigestResponse
    errors: [GenericServerError, PrimitivesError]
}

/// Compute an HMAC.
operation Hmac {
    input: HmacRequest
    output: HmacResponse
    errors: [GenericServerError, PrimitivesError]
}

/// Derive key material using HKDF (extract + expand combined).
operation Hkdf {
    input: HkdfRequest
    output: HkdfResponse
    errors: [GenericServerError, PrimitivesError]
}

/// Derive key material using KBKDF in counter mode with HMAC
/// (NIST SP 800-108 §4.1).
operation KbkdfCtrHmac {
    input: KbkdfCtrHmacRequest
    output: KbkdfCtrHmacResponse
    errors: [GenericServerError, PrimitivesError]
}

/// Generate a fresh ECDSA key pair.
operation EcdsaGenerateKeyPair {
    input: EcdsaGenerateKeyPairRequest
    output: EcdsaGenerateKeyPairResponse
    errors: [GenericServerError, PrimitivesError]
}

/// Sign a message with ECDSA.
operation EcdsaSign {
    input: EcdsaSignRequest
    output: EcdsaSignResponse
    errors: [GenericServerError, PrimitivesError]
}

/// Verify an ECDSA signature.
operation EcdsaVerify {
    input: EcdsaVerifyRequest
    output: EcdsaVerifyResponse
    errors: [GenericServerError, PrimitivesError]
}

// ===========================================================================
// Enumerations
// ===========================================================================

/// AES-GCM algorithm variants.
enum AesAlgorithm {
    AES_128_GCM
    AES_192_GCM
    AES_256_GCM
}

/// Digest (hash) algorithm variants.
enum DigestAlgorithm {
    SHA_256
    SHA_384
    SHA_512
}

/// ECDSA signature algorithm variants.
enum EcdsaAlgorithm {
    ECDSA_P256
    ECDSA_P384
}

// ===========================================================================
// AES shapes
// ===========================================================================

@input
structure AesEncryptRequest {
    @required
    algorithm: AesAlgorithm

    /// GCM initialization vector (12 bytes).
    @required
    iv: Blob

    /// AES key (16, 24, or 32 bytes depending on algorithm).
    @required
    key: Blob

    /// Plaintext to encrypt.
    @required
    message: Blob

    /// Additional authenticated data.
    @required
    aad: Blob
}

@output
structure AesEncryptResponse {
    /// Ciphertext (same length as message, does NOT include auth tag).
    @required
    ciphertext: Blob

    /// Authentication tag (16 bytes for GCM).
    @required
    authTag: Blob
}

@input
structure AesDecryptRequest {
    @required
    algorithm: AesAlgorithm

    @required
    key: Blob

    /// Ciphertext to decrypt (without auth tag).
    @required
    ciphertext: Blob

    /// Authentication tag to verify.
    @required
    authTag: Blob

    /// GCM initialization vector (12 bytes).
    @required
    iv: Blob

    /// Additional authenticated data.
    @required
    aad: Blob
}

@output
structure AesDecryptResponse {
    @required
    plaintext: Blob
}

// ===========================================================================
// Random shapes
// ===========================================================================

@input
structure GenerateRandomBytesRequest {
    /// Number of random bytes to generate.
    @required
    length: Integer
}

@output
structure GenerateRandomBytesResponse {
    @required
    data: Blob
}

// ===========================================================================
// Digest shapes
// ===========================================================================

@input
structure DigestRequest {
    @required
    algorithm: DigestAlgorithm

    @required
    data: Blob
}

@output
structure DigestResponse {
    @required
    digest: Blob
}

// ===========================================================================
// HMAC shapes
// ===========================================================================

@input
structure HmacRequest {
    @required
    algorithm: DigestAlgorithm

    @required
    key: Blob

    @required
    message: Blob
}

@output
structure HmacResponse {
    @required
    digest: Blob
}

// ===========================================================================
// HKDF shapes
// ===========================================================================

@input
structure HkdfRequest {
    @required
    algorithm: DigestAlgorithm

    @required
    salt: Blob

    /// Input key material.
    @required
    ikm: Blob

    /// Context / application-specific info.
    @required
    info: Blob

    /// Desired output length in bytes (must be 16, 24, or 32).
    @required
    expectedLength: Integer
}

@output
structure HkdfResponse {
    @required
    okm: Blob
}

// ===========================================================================
// KBKDF-CTR-HMAC shapes
// ===========================================================================

@input
structure KbkdfCtrHmacRequest {
    @required
    algorithm: DigestAlgorithm

    /// Input key material.
    @required
    ikm: Blob

    /// Fixed info (Label || 0x00 || Context || L per NIST SP 800-108).
    @required
    info: Blob

    /// Desired output length in bytes.
    @required
    expectedLength: Integer
}

@output
structure KbkdfCtrHmacResponse {
    @required
    okm: Blob
}

// ===========================================================================
// ECDSA shapes
// ===========================================================================

@input
structure EcdsaGenerateKeyPairRequest {
    @required
    algorithm: EcdsaAlgorithm
}

@output
structure EcdsaGenerateKeyPairResponse {
    /// X9.62 compressed public key.
    @required
    verificationKey: Blob

    /// DER-encoded private key (RFC 5915).
    @required
    signingKey: Blob
}

@input
structure EcdsaSignRequest {
    @required
    algorithm: EcdsaAlgorithm

    /// DER-encoded private key.
    @required
    signingKey: Blob

    @required
    message: Blob
}

@output
structure EcdsaSignResponse {
    /// DER-encoded ECDSA signature.
    @required
    signature: Blob
}

@input
structure EcdsaVerifyRequest {
    @required
    algorithm: EcdsaAlgorithm

    /// X9.62 compressed public key.
    @required
    verificationKey: Blob

    @required
    message: Blob

    /// DER-encoded ECDSA signature.
    @required
    signature: Blob
}

@output
structure EcdsaVerifyResponse {
    @required
    valid: Boolean
}

// ===========================================================================
// Errors
// ===========================================================================

/// Framework-side failure (bad request, unknown operation, malformed input).
@error("client")
structure GenericServerError {
    @required
    message: String
}

/// A failure forwarded from the underlying cryptographic primitives library.
@error("client")
structure PrimitivesError {
    @required
    message: String
}
