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
        BatchWriteItemInputTransform
        TransactWriteItemsInputTransform
        ScanOutputTransform
        QueryOutputTransform
        BatchGetItemOutputTransform
        ExecuteStatementInputTransform
        BatchExecuteStatementInputTransform
        ExecuteTransactionInputTransform
        BatchWriteItemOutputTransform
        ScanInputTransform
        QueryInputTransform
        UpdateItemInputTransform
        DeleteItemInputTransform
        CreateStructuredClient
        EncryptStructure
        DecryptStructure
        EncryptPathStructure
        DecryptPathStructure
        ResolveAuthActions
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

/// Encrypt-before hook for a batch write: transform a DynamoDB BatchWriteItem
/// input, encrypting the item of every PutRequest across all tables. Delete
/// requests pass through unchanged.
operation BatchWriteItemInputTransform {
    input: BatchWriteItemInputTransformRequest
    output: BatchWriteItemInputTransformResponse
    errors: [
        GenericServerError
        DBESDKClientError
    ]
}

/// Encrypt-before hook for a transactional write: transform a DynamoDB
/// TransactWriteItems input, encrypting the item of every Put in the
/// transaction.
operation TransactWriteItemsInputTransform {
    input: TransactWriteItemsInputTransformRequest
    output: TransactWriteItemsInputTransformResponse
    errors: [
        GenericServerError
        DBESDKClientError
    ]
}

/// Decrypt-after hook for a scan: transform a DynamoDB Scan output, decrypting
/// every returned item.
operation ScanOutputTransform {
    input: ScanOutputTransformRequest
    output: ScanOutputTransformResponse
    errors: [
        GenericServerError
        DBESDKClientError
    ]
}

/// Decrypt-after hook for a query: transform a DynamoDB Query output, decrypting
/// every returned item.
operation QueryOutputTransform {
    input: QueryOutputTransformRequest
    output: QueryOutputTransformResponse
    errors: [
        GenericServerError
        DBESDKClientError
    ]
}

/// Decrypt-after hook for a batch get: transform a DynamoDB BatchGetItem output,
/// decrypting every returned item across all tables.
operation BatchGetItemOutputTransform {
    input: BatchGetItemOutputTransformRequest
    output: BatchGetItemOutputTransformResponse
    errors: [
        GenericServerError
        DBESDKClientError
    ]
}

/// Validate-before hook for a PartiQL ExecuteStatement: the DBE library rejects
/// the request (raising a DBESDKClientError) when the statement targets an
/// encrypted table, because a PartiQL statement cannot be transformed to
/// operate over encrypted attributes. A statement targeting a non-encrypted
/// table passes through unchanged.
operation ExecuteStatementInputTransform {
    input: ExecuteStatementInputTransformRequest
    output: ExecuteStatementInputTransformResponse
    errors: [
        GenericServerError
        DBESDKClientError
    ]
}

/// Validate-before hook for a PartiQL BatchExecuteStatement: rejected when any
/// statement targets an encrypted table.
operation BatchExecuteStatementInputTransform {
    input: BatchExecuteStatementInputTransformRequest
    output: BatchExecuteStatementInputTransformResponse
    errors: [
        GenericServerError
        DBESDKClientError
    ]
}

/// Validate-before hook for a PartiQL ExecuteTransaction: rejected when any
/// transact statement targets an encrypted table.
operation ExecuteTransactionInputTransform {
    input: ExecuteTransactionInputTransformRequest
    output: ExecuteTransactionInputTransformResponse
    errors: [
        GenericServerError
        DBESDKClientError
    ]
}

/// Decrypt-after hook for a batch write: transform a DynamoDB BatchWriteItem
/// output. Any items DynamoDB could not process are returned in
/// UnprocessedItems still in their encrypted form; each such PutRequest item
/// MUST be restored to its original plaintext value (matched against the
/// original request by primary key) so a caller can resubmit it. A response
/// with no UnprocessedItems is returned unchanged.
operation BatchWriteItemOutputTransform {
    input: BatchWriteItemOutputTransformRequest
    output: BatchWriteItemOutputTransformResponse
    errors: [
        GenericServerError
        DBESDKClientError
    ]
}

/// Modify-before hook for a scan: transform a DynamoDB Scan input, rewriting
/// any FilterExpression reference to a beaconed attribute into the beacon
/// attribute (`aws_dbe_b_<name>`) and replacing the compared value with its
/// beacon. A scan against a table with no matching beacon config passes
/// through unchanged.
operation ScanInputTransform {
    input: ScanInputTransformRequest
    output: ScanInputTransformResponse
    errors: [
        GenericServerError
        DBESDKClientError
    ]
}

/// Modify-before hook for a query: transform a DynamoDB Query input, rewriting
/// KeyCondition/Filter expression references to beaconed attributes into their
/// beacons.
operation QueryInputTransform {
    input: QueryInputTransformRequest
    output: QueryInputTransformResponse
    errors: [
        GenericServerError
        DBESDKClientError
    ]
}

/// Validate-before hook for an UpdateItem: the DBE library rejects the request
/// (raising a DBESDKClientError) when the UpdateExpression references any signed
/// attribute, because updating a signed attribute would invalidate the item
/// signature. An UpdateExpression touching only unsigned (DO_NOTHING /
/// unconfigured) attributes passes through unchanged.
operation UpdateItemInputTransform {
    input: UpdateItemInputTransformRequest
    output: UpdateItemInputTransformResponse
    errors: [
        GenericServerError
        DBESDKClientError
    ]
}

/// Validate-before hook for a DeleteItem: the DBE library rejects the request
/// (raising a DBESDKClientError) when the ConditionExpression references any
/// encrypted attribute, because an encrypted attribute's ciphertext cannot be
/// compared server-side. A ConditionExpression over only non-encrypted
/// (signed-but-not-encrypted or unsigned) attributes passes through unchanged.
operation DeleteItemInputTransform {
    input: DeleteItemInputTransformRequest
    output: DeleteItemInputTransformResponse
    errors: [
        GenericServerError
        DBESDKClientError
    ]
}

/// Construct and register a Structured Encryption client (the raw structured
/// layer beneath the item encryptor), returning a ClientId. The keyring/CMM in
/// the config builds the CMM the Encrypt/DecryptStructure operations use.
operation CreateStructuredClient {
    input: CreateStructuredClientRequest
    output: CreateStructuredClientResponse
    errors: [
        GenericServerError
        DBESDKClientError
    ]
}

/// Encrypt a raw structured-data map with the referenced Structured Encryption
/// client, per the given Crypto Schema (per-field ENCRYPT_AND_SIGN / SIGN_ONLY /
/// SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT / DO_NOTHING).
operation EncryptStructure {
    input: EncryptStructureRequest
    output: EncryptStructureResponse
    errors: [
        GenericServerError
        DBESDKClientError
    ]
}

/// Decrypt a raw structured-data map produced by EncryptStructure, verifying the
/// signature per the given Authenticate Schema and decrypting encrypted terminals.
operation DecryptStructure {
    input: DecryptStructureRequest
    output: DecryptStructureResponse
    errors: [
        GenericServerError
        DBESDKClientError
    ]
}

/// Encrypt a raw structured-data list keyed by Path (the path-based form of
/// EncryptStructure): each Crypto Item carries a Path, a terminal, and a Crypto
/// Action, and the encrypted list is returned in the same shape.
operation EncryptPathStructure {
    input: EncryptPathStructureRequest
    output: EncryptPathStructureResponse
    errors: [
        GenericServerError
        DBESDKClientError
    ]
}

/// Decrypt a path-keyed structured-data list produced by EncryptPathStructure,
/// verifying the signature per each Auth Item's Authenticate Action.
operation DecryptPathStructure {
    input: DecryptPathStructureRequest
    output: DecryptPathStructureResponse
    errors: [
        GenericServerError
        DBESDKClientError
    ]
}

/// Resolve, from an Auth List and the serialized header bytes, the Crypto Action
/// the header's Crypto Legend assigns to each terminal. Needs no CMM.
operation ResolveAuthActions {
    input: ResolveAuthActionsRequest
    output: ResolveAuthActionsResponse
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

    /// Optional additional (table name → crypto config) entries. When present,
    /// the transforms client is built from a `DynamoDbTablesEncryptionConfig`
    /// holding the primary table plus each of these — so one transforms client
    /// spans several tables, each with its own independent crypto config
    /// (including its own `algorithmSuiteId`).
    additionalTables: TransformsTableConfigList
}

/// One additional (table name, crypto config) entry for a multi-table
/// transforms client.
structure TransformsTableConfig {
    @required
    tableName: String

    @required
    config: DBEClientConfig
}

list TransformsTableConfigList {
    member: TransformsTableConfig
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

@input
structure BatchWriteItemInputTransformRequest {
    @required
    clientId: ClientId

    /// The DynamoDB BatchWriteItem input to transform (encrypt-before).
    @required
    sdkInput: BatchWriteItemInput
}

@output
structure BatchWriteItemInputTransformResponse {
    /// The transformed BatchWriteItem input, whose PutRequest items are now
    /// encrypted.
    @required
    transformedInput: BatchWriteItemInput
}

@input
structure TransactWriteItemsInputTransformRequest {
    @required
    clientId: ClientId

    /// The DynamoDB TransactWriteItems input to transform (encrypt-before).
    @required
    sdkInput: TransactWriteItemsInput
}

@output
structure TransactWriteItemsInputTransformResponse {
    /// The transformed TransactWriteItems input, whose Put items are now
    /// encrypted.
    @required
    transformedInput: TransactWriteItemsInput
}

@input
structure ScanOutputTransformRequest {
    @required
    clientId: ClientId

    /// The DynamoDB Scan output to transform (decrypt-after).
    @required
    sdkOutput: ScanOutput

    /// The original DynamoDB Scan input that produced `sdkOutput`.
    @required
    originalInput: ScanInput
}

@output
structure ScanOutputTransformResponse {
    /// The transformed Scan output, whose items are now decrypted.
    @required
    transformedOutput: ScanOutput
}

@input
structure QueryOutputTransformRequest {
    @required
    clientId: ClientId

    /// The DynamoDB Query output to transform (decrypt-after).
    @required
    sdkOutput: QueryOutput

    /// The original DynamoDB Query input that produced `sdkOutput`.
    @required
    originalInput: QueryInput
}

@output
structure QueryOutputTransformResponse {
    /// The transformed Query output, whose items are now decrypted.
    @required
    transformedOutput: QueryOutput
}

@input
structure BatchGetItemOutputTransformRequest {
    @required
    clientId: ClientId

    /// The DynamoDB BatchGetItem output to transform (decrypt-after).
    @required
    sdkOutput: BatchGetItemOutput

    /// The original DynamoDB BatchGetItem input that produced `sdkOutput`.
    @required
    originalInput: BatchGetItemInput
}

@output
structure BatchGetItemOutputTransformResponse {
    /// The transformed BatchGetItem output, whose items are now decrypted.
    @required
    transformedOutput: BatchGetItemOutput
}

@input
structure ExecuteStatementInputTransformRequest {
    @required
    clientId: ClientId

    /// The DynamoDB ExecuteStatement input to validate (validate-before).
    @required
    sdkInput: ExecuteStatementInput
}

@output
structure ExecuteStatementInputTransformResponse {
    /// The unchanged ExecuteStatement input (only returned when the statement
    /// targets no encrypted table; an encrypted-table target fails instead).
    @required
    transformedInput: ExecuteStatementInput
}

@input
structure BatchExecuteStatementInputTransformRequest {
    @required
    clientId: ClientId

    /// The DynamoDB BatchExecuteStatement input to validate (validate-before).
    @required
    sdkInput: BatchExecuteStatementInput
}

@output
structure BatchExecuteStatementInputTransformResponse {
    /// The unchanged BatchExecuteStatement input (only returned when no
    /// statement targets an encrypted table).
    @required
    transformedInput: BatchExecuteStatementInput
}

@input
structure ExecuteTransactionInputTransformRequest {
    @required
    clientId: ClientId

    /// The DynamoDB ExecuteTransaction input to validate (validate-before).
    @required
    sdkInput: ExecuteTransactionInput
}

@output
structure ExecuteTransactionInputTransformResponse {
    /// The unchanged ExecuteTransaction input (only returned when no transact
    /// statement targets an encrypted table).
    @required
    transformedInput: ExecuteTransactionInput
}

@input
structure BatchWriteItemOutputTransformRequest {
    @required
    clientId: ClientId

    /// The DynamoDB BatchWriteItem output to transform (decrypt-after).
    @required
    sdkOutput: BatchWriteItemOutput

    /// The original (plaintext) DynamoDB BatchWriteItem input, used to restore
    /// each unprocessed item to its plaintext value by primary-key match.
    @required
    originalInput: BatchWriteItemInput
}

@output
structure BatchWriteItemOutputTransformResponse {
    /// The transformed BatchWriteItem output, whose UnprocessedItems (if any)
    /// are now restored to their plaintext values.
    @required
    transformedOutput: BatchWriteItemOutput
}

@input
structure ScanInputTransformRequest {
    @required
    clientId: ClientId

    @required
    sdkInput: ScanInput
}

@output
structure ScanInputTransformResponse {
    /// The transformed Scan input, whose beacon-attribute filter references are
    /// rewritten to the beacon.
    @required
    transformedInput: ScanInput
}

@input
structure QueryInputTransformRequest {
    @required
    clientId: ClientId

    @required
    sdkInput: QueryInput
}

@output
structure QueryInputTransformResponse {
    /// The transformed Query input, whose beacon-attribute expression
    /// references are rewritten to the beacon.
    @required
    transformedInput: QueryInput
}

@input
structure UpdateItemInputTransformRequest {
    @required
    clientId: ClientId

    /// The DynamoDB UpdateItem input to validate (validate-before).
    @required
    sdkInput: UpdateItemInput
}

@output
structure UpdateItemInputTransformResponse {
    /// The unchanged UpdateItem input (only returned when the UpdateExpression
    /// references no signed attribute; a signed-attribute update fails instead).
    @required
    transformedInput: UpdateItemInput
}

@input
structure DeleteItemInputTransformRequest {
    @required
    clientId: ClientId

    /// The DynamoDB DeleteItem input to validate (validate-before).
    @required
    sdkInput: DeleteItemInput
}

@output
structure DeleteItemInputTransformResponse {
    /// The unchanged DeleteItem input (only returned when the ConditionExpression
    /// references no encrypted attribute; an encrypted-attribute condition fails
    /// instead).
    @required
    transformedInput: DeleteItemInput
}

// ===========================================================================
// Structured Encryption (§0.3.5) request / response + data shapes.
// ===========================================================================

@input
structure CreateStructuredClientRequest {
    /// Crypto config whose keyring/CMM builds the CMM used by Encrypt/Decrypt
    /// Structure. Reuses the item-encryptor config shape; only the keyring/cmm
    /// (and optional algorithmSuiteId) are consulted.
    @required
    config: DBEClientConfig
}

@output
structure CreateStructuredClientResponse {
    @required
    clientId: ClientId
}

@input
structure EncryptStructureRequest {
    @required
    clientId: ClientId

    /// A logical table name bound into the structured-encryption context.
    @required
    tableName: String

    /// The plaintext structured data: a map of field name to a terminal
    /// (opaque value bytes + a 2-byte type id).
    @required
    plaintextStructure: StructuredDataMap

    /// Per-field Crypto Action.
    @required
    cryptoSchema: CryptoSchemaMap
}

@output
structure EncryptStructureResponse {
    /// The encrypted structured data: ENCRYPT_AND_SIGN terminals now hold
    /// ciphertext, plus the added header/footer terminals.
    @required
    encryptedStructure: StructuredDataMap
}

@input
structure DecryptStructureRequest {
    @required
    clientId: ClientId

    @required
    tableName: String

    /// The encrypted structured data produced by EncryptStructure.
    @required
    encryptedStructure: StructuredDataMap

    /// Per-field Authenticate Action (which fields are within the signature
    /// scope), as required to verify + decrypt.
    @required
    authenticateSchema: AuthenticateSchemaMap
}

@output
structure DecryptStructureResponse {
    /// The recovered plaintext structured data (header/footer terminals stripped).
    @required
    plaintextStructure: StructuredDataMap
}

structure EncryptPathStructureRequest {
    @required
    clientId: ClientId

    @required
    tableName: String

    /// The plaintext structured data as a list of Crypto Items (Path + terminal
    /// + Crypto Action) rather than a flat map.
    @required
    plaintextStructure: PathCryptoList
}

structure EncryptPathStructureResponse {
    /// The encrypted Crypto List: ENCRYPT_AND_SIGN terminals now hold ciphertext,
    /// plus the added header/footer items.
    @required
    encryptedStructure: PathCryptoList
}

structure DecryptPathStructureRequest {
    @required
    clientId: ClientId

    @required
    tableName: String

    /// The encrypted data as an Auth List (Path + terminal + Authenticate
    /// Action) produced from an EncryptPathStructure result.
    @required
    encryptedStructure: PathAuthList
}

structure DecryptPathStructureResponse {
    /// The recovered plaintext Crypto List (header/footer items stripped).
    @required
    plaintextStructure: PathCryptoList
}

structure ResolveAuthActionsRequest {
    @required
    tableName: String

    /// The Auth List whose per-terminal Crypto Actions are to be resolved.
    @required
    authActions: PathAuthList

    /// The serialized structured-encryption header (the aws_dbe_head terminal's
    /// value), carrying the Crypto Legend that assigns each terminal's action.
    @required
    headerBytes: Blob
}

structure ResolveAuthActionsResponse {
    /// Each input terminal with the Crypto Action resolved from the header.
    @required
    cryptoActions: PathCryptoList
}

/// A Path: an ordered list of structure-member names locating a terminal. Only
/// structure segments (member names) are modeled, matching the DBE Path union's
/// single supported variant.
list PathSegments {
    member: String
}

/// One path-keyed Crypto Item: a Path, its terminal, and a Crypto Action.
structure PathCryptoItem {
    @required
    path: PathSegments

    @required
    data: StructuredDataTerminal

    @required
    action: CryptoAction
}

list PathCryptoList {
    member: PathCryptoItem
}

/// One path-keyed Auth Item: a Path, its terminal, and an Authenticate Action.
structure PathAuthItem {
    @required
    path: PathSegments

    @required
    data: StructuredDataTerminal

    @required
    action: AuthenticateAction
}

list PathAuthList {
    member: PathAuthItem
}

/// One structured-data terminal: opaque value bytes plus a 2-byte type id the
/// caller uses to interpret the value.
structure StructuredDataTerminal {
    @required
    value: Blob

    @required
    typeId: Blob
}

map StructuredDataMap {
    key: String
    value: StructuredDataTerminal
}

map CryptoSchemaMap {
    key: String
    value: CryptoAction
}

/// Whether a field is within the signature scope on decrypt.
enum AuthenticateAction {
    SIGN
    DO_NOT_SIGN
}

map AuthenticateSchemaMap {
    key: String
    value: AuthenticateAction
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

/// A DynamoDB UpdateItem input. Carries the primary key plus the optional
/// UpdateExpression / ConditionExpression and their name/value maps — the
/// validate-before transform inspects the UpdateExpression for references to
/// signed attributes.
structure UpdateItemInput {
    @required
    tableName: String

    @required
    key: DDBItem

    updateExpression: String

    conditionExpression: String

    expressionAttributeNames: ExpressionAttributeNameMap

    expressionAttributeValues: DDBItem
}

/// A DynamoDB DeleteItem input. Carries the primary key plus the optional
/// ConditionExpression and its name/value maps — the validate-before transform
/// inspects the ConditionExpression for references to encrypted attributes.
structure DeleteItemInput {
    @required
    tableName: String

    @required
    key: DDBItem

    conditionExpression: String

    expressionAttributeNames: ExpressionAttributeNameMap

    expressionAttributeValues: DDBItem
}

/// A DynamoDB BatchWriteItem input: a map of table name → the write requests
/// against that table.
structure BatchWriteItemInput {
    @required
    requestItems: WriteRequestMap
}

/// Map of table name → its list of write requests, mirroring the DynamoDB
/// BatchWriteItem `RequestItems` shape.
map WriteRequestMap {
    key: String
    value: WriteRequestList
}

list WriteRequestList {
    member: WriteRequest
}

/// One BatchWriteItem write request: exactly one of a put or a delete, matching
/// the DynamoDB WriteRequest shape. The encrypt-before transform encrypts a
/// PutRequest's item and passes a DeleteRequest through unchanged.
structure WriteRequest {
    putRequest: PutRequest
    deleteRequest: DeleteRequest
}

/// A BatchWriteItem PutRequest: the item to write (the table is the enclosing
/// WriteRequestMap key).
structure PutRequest {
    @required
    item: DDBItem
}

/// A BatchWriteItem DeleteRequest: the primary key to delete.
structure DeleteRequest {
    @required
    key: DDBItem
}

/// A DynamoDB BatchWriteItem output: the items DynamoDB could not process,
/// keyed by table name (same shape as the input's requestItems). Absent when
/// everything was written.
structure BatchWriteItemOutput {
    unprocessedItems: WriteRequestMap
}

/// A DynamoDB TransactWriteItems input: the list of transactional write
/// actions.
structure TransactWriteItemsInput {
    @required
    transactItems: TransactWriteItemList
}

list TransactWriteItemList {
    member: TransactWriteItem
}

/// One action in a TransactWriteItems transaction. Only the `Put` action is
/// modeled — the encrypt-before transform encrypts a Put's item; the
/// Update / Delete / ConditionCheck actions carry no full item to encrypt and
/// are added in a later sub-round.
structure TransactWriteItem {
    put: Put
}

/// A TransactWriteItems Put action: the target table and the item to write.
structure Put {
    @required
    tableName: String

    @required
    item: DDBItem
}

/// An ordered list of DDB items, used by the read-path output transforms.
list ItemList {
    member: DDBItem
}

/// A DynamoDB Scan input: the scanned table (the transform needs it to find the
/// table's crypto config). For the input (modify-before) transform it also
/// carries the optional FilterExpression and its name/value maps, whose
/// beacon-attribute references are rewritten to beacons.
structure ScanInput {
    @required
    tableName: String

    filterExpression: String

    expressionAttributeNames: ExpressionAttributeNameMap

    expressionAttributeValues: DDBItem
}

/// A DynamoDB Scan output: the returned items (absent when the scan matched
/// nothing).
structure ScanOutput {
    items: ItemList
}

/// A DynamoDB Query input. For the input (modify-before) transform it carries
/// the optional KeyCondition/Filter expressions and their name/value maps,
/// whose beacon-attribute references are rewritten to beacons.
structure QueryInput {
    @required
    tableName: String

    keyConditionExpression: String

    filterExpression: String

    expressionAttributeNames: ExpressionAttributeNameMap

    expressionAttributeValues: DDBItem
}

/// DynamoDB ExpressionAttributeNames: placeholder (`#x`) → real attribute name.
map ExpressionAttributeNameMap {
    key: String
    value: String
}

/// A DynamoDB Query output: the returned items (absent when the query matched
/// nothing).
structure QueryOutput {
    items: ItemList
}

/// A DynamoDB BatchGetItem input: a map of table name → the keys requested from
/// that table.
structure BatchGetItemInput {
    @required
    requestItems: KeysAndAttributesMap
}

map KeysAndAttributesMap {
    key: String
    value: KeysAndAttributes
}

/// The keys requested from one table in a BatchGetItem.
structure KeysAndAttributes {
    @required
    keys: ItemList
}

/// A DynamoDB BatchGetItem output: a map of table name → the items returned for
/// that table.
structure BatchGetItemOutput {
    responses: BatchGetResponseMap
}

map BatchGetResponseMap {
    key: String
    value: ItemList
}

/// A DynamoDB ExecuteStatement input. Only the PartiQL `statement` is modeled —
/// validate-before parses the target table out of the statement text and needs
/// nothing else.
structure ExecuteStatementInput {
    @required
    statement: String
}

/// A DynamoDB BatchExecuteStatement input: the batch of PartiQL statements.
structure BatchExecuteStatementInput {
    @required
    statements: BatchStatementRequestList
}

list BatchStatementRequestList {
    member: BatchStatementRequest
}

/// One statement in a BatchExecuteStatement.
structure BatchStatementRequest {
    @required
    statement: String
}

/// A DynamoDB ExecuteTransaction input: the transactional PartiQL statements.
structure ExecuteTransactionInput {
    @required
    transactStatements: ParameterizedStatementList
}

list ParameterizedStatementList {
    member: ParameterizedStatement
}

/// One statement in an ExecuteTransaction.
structure ParameterizedStatement {
    @required
    statement: String
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

    /// Optional searchable-encryption (beacon) configuration. Only honored by a
    /// transforms client (CreateTransformsClient); the item encryptor ignores
    /// it. When present, encrypted/signed attributes named by its beacons gain
    /// an `aws_dbe_b_<name>` beacon attribute on write, and Scan/Query
    /// FilterExpression references to those attributes are rewritten to the
    /// beacon on the read path.
    search: SearchConfig
}

// ===========================================================================
// Searchable encryption (beacons). Minimal shape: a single beacon version with
// standard beacons keyed by a single beacon key store. Compound / virtual
// beacons and multi key stores are added in later sub-rounds.
// ===========================================================================
structure SearchConfig {
    /// The beacon versions. DBE currently supports exactly one.
    @required
    versions: BeaconVersionList

    /// The beacon version written on encrypt (1-based). Defaults to 1.
    writeVersion: Integer
}

list BeaconVersionList {
    member: BeaconVersion
}

structure BeaconVersion {
    /// The beacon version number (1-based).
    @required
    version: Integer

    /// The branch-key store that holds the beacon keys.
    @required
    keyStore: BeaconKeyStore

    /// Where the beacon key material comes from.
    @required
    keySource: BeaconKeySource

    /// The standard (single-attribute) beacons defined for this version.
    standardBeacons: StandardBeaconList

    /// The compound beacons (assembled from encrypted/signed parts) defined for
    /// this version.
    compoundBeacons: CompoundBeaconList

    /// The virtual fields (values derived from other attributes) defined for
    /// this version. A standard beacon can then be built over a virtual field.
    virtualFields: VirtualFieldList

    /// Encrypted parts available to any compound beacon in this version. Each
    /// references a standard beacon by name and carries a prefix.
    encryptedParts: EncryptedPartList

    /// Signed (plaintext) parts available to any compound beacon in this
    /// version. Each carries a prefix and an optional source location.
    signedParts: SignedPartList

    /// The maximum number of partitions any beacon in this version may be
    /// divided across. Only honored by servers supporting the
    /// `beacon-partitions` feature.
    maximumNumberOfPartitions: Integer

    /// The partitions applied to any beacon that does not set its own
    /// `numberOfPartitions`. Must satisfy 0 < default < maximum, and may only be
    /// set when `maximumNumberOfPartitions` is also set. Only honored by servers
    /// supporting the `beacon-partitions` feature.
    defaultNumberOfPartitions: Integer
}

/// Configuration for the DynamoDB branch-key store that holds beacon keys —
/// the same key store the AWS KMS Hierarchical keyring uses. The DynamoDB and
/// KMS clients are constructed server-side from these serializable fields.
structure BeaconKeyStore {
    @required
    ddbTableName: String

    @required
    logicalKeyStoreName: String

    @required
    kmsKeyArn: String
}

/// The beacon key source. Exactly one variant is expected to be set at runtime;
/// this sub-round wires the single-key-store source.
structure BeaconKeySource {
    single: SingleKeyStore
}

structure SingleKeyStore {
    /// The branch-key id whose beacon key derives the beacons.
    @required
    keyId: String

    /// Beacon-key cache TTL, in seconds.
    @required
    cacheTtlSeconds: Integer
}

list StandardBeaconList {
    member: StandardBeacon
}

/// A standard beacon over one attribute, making it queryable by equality
/// without decryption.
structure StandardBeacon {
    /// The name of the beacon, and of the attribute it beacons.
    @required
    name: String

    /// The beacon length in bits (the truncated-HMAC output width).
    @required
    length: Integer

    /// Optional DynamoDB document path to the value this beacon calculates over.
    /// Defaults to the attribute named by `name`; set it to beacon over a
    /// virtual field (whose name is not a stored attribute).
    loc: String

    /// Optional number of partitions this beacon is divided across. Must be less
    /// than the version's `maximumNumberOfPartitions`. Only honored by servers
    /// whose library supports beacon partitions (the `beacon-partitions`
    /// feature); a server that declares that feature unsupported ignores it.
    numberOfPartitions: Integer

    /// Optional beacon style (PartOnly / Shared / AsSet).
    style: BeaconStyle
}

/// A standard beacon's style (exactly one member set). Models PartOnly (usable
/// only within a compound beacon, never stored standalone), Shared (calculates
/// its value as another named beacon so the two are comparable), AsSet (beacons
/// a Set attribute element-wise, stored as a Set), and SharedSet (both Shared
/// and AsSet).
structure BeaconStyle {
    partOnly: PartOnly
    shared: Shared
    asSet: AsSet
    sharedSet: SharedSet
}

/// A beacon usable only as part of a compound beacon; never stored standalone.
structure PartOnly {}

/// A beacon over a Set attribute, stored as a Set of per-element beacon values.
structure AsSet {}

/// A beacon that calculates its value as the {@code other} beacon (same length),
/// so the two beacons are directly comparable.
structure Shared {
    @required
    other: String
}

/// Both {@code Shared} and {@code AsSet}: a beacon over a Set attribute that
/// calculates its element values as the {@code other} beacon.
structure SharedSet {
    @required
    other: String
}

list CompoundBeaconList {
    member: CompoundBeacon
}

/// A compound beacon assembled from ordered parts (each an encrypted or signed
/// part), joined by a split character. Written to `aws_dbe_b_<name>`.
structure CompoundBeacon {
    /// The name of the compound beacon.
    @required
    name: String

    /// The single character joining parts of the assembled beacon value. Must
    /// not appear in any part's prefix or signed value.
    @required
    split: String

    /// The ordered constructors; the first whose required parts are all present
    /// builds the beacon.
    constructors: ConstructorList

    /// Encrypted parts local to this compound beacon (an alternative to the
    /// version-level `encryptedParts`).
    encrypted: EncryptedPartList

    /// Signed parts local to this compound beacon (an alternative to the
    /// version-level `signedParts`).
    signed: SignedPartList
}

list ConstructorList {
    member: Constructor
}

/// One way to construct a compound beacon: an ordered list of parts.
structure Constructor {
    @required
    parts: ConstructorPartList
}

list ConstructorPartList {
    member: ConstructorPart
}

/// A part of a compound-beacon construction, naming an encrypted or signed part
/// and whether it is required for this construction.
structure ConstructorPart {
    @required
    name: String

    @required
    required: Boolean
}

list EncryptedPartList {
    member: EncryptedPart
}

/// An encrypted part of a compound beacon: the name of a standard beacon whose
/// value it holds, plus the prefix written with it.
structure EncryptedPart {
    @required
    name: String

    @required
    prefix: String
}

list SignedPartList {
    member: SignedPart
}

/// A signed (plaintext) part of a compound beacon: a name, the prefix written
/// with it, and an optional source location (defaults to `name`).
structure SignedPart {
    @required
    name: String

    @required
    prefix: String

    loc: String
}

list VirtualFieldList {
    member: VirtualField
}

/// A virtual field: a value derived by concatenating other attributes' values,
/// usable as the source for a standard beacon.
structure VirtualField {
    @required
    name: String

    @required
    parts: VirtualPartList
}

list VirtualPartList {
    member: VirtualPart
}

/// One part of a virtual field: the DynamoDB document path of a source
/// attribute, with an optional ordered list of transforms applied to its value.
structure VirtualPart {
    @required
    loc: String

    trans: VirtualTransformList
}

list VirtualTransformList {
    member: VirtualTransform
}

/// A virtual-part transformation (exactly one member set). Models the Upper,
/// Lower, Insert, GetPrefix, GetSuffix, GetSubstring, GetSegment, and GetSegments
/// transforms; transforms treat the value as a string.
structure VirtualTransform {
    upper: Upper
    lower: Lower
    insert: Insert
    prefix: GetPrefix
    suffix: GetSuffix
    substring: GetSubstring
    segment: GetSegment
    segments: GetSegments
}

/// Convert ASCII characters to upper case (no parameters).
structure Upper {}

/// Convert ASCII characters to lower case (no parameters).
structure Lower {}

/// Append a literal string to the value.
structure Insert {
    @required
    literal: String
}

/// Keep the first {@code length} characters (negative excludes from the end).
structure GetPrefix {
    @required
    length: Integer
}

/// Keep the last {@code length} characters (negative excludes from the front).
structure GetSuffix {
    @required
    length: Integer
}

/// Keep the {@code [low, high)} character range, 0-based; negative indices count
/// from the end (-1 is the last character).
structure GetSubstring {
    @required
    low: Integer

    @required
    high: Integer
}

/// Split the value on {@code split} and return one segment ({@code index},
/// 0-based; negative counts from the end).
structure GetSegment {
    @required
    split: String

    @required
    index: Integer
}

/// Split the value on {@code split} and return the {@code [low, high)} segment
/// range (0-based; negative indices count from the end).
structure GetSegments {
    @required
    split: String

    @required
    low: Integer

    @required
    high: Integer
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
