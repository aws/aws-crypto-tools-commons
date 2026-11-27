# Writing an MPL test server test

These tests send MPL calls, such as OnEncrypt, to each language's test server.
Each test runs once for each language, so one test checks every MPL at once.
This page says how to write one.

## One spec rule per test, with both sides

- A test checks one rule from the spec.
- It shows the rule holding (the side that succeeds) and the rule broken (the side that fails).
  A test with only the failing side passes for a keyring that fails every call.
- Put the duvet annotation for the rule at the top of the test, or right above the assertion that checks it.

```java
// a test checks one rule, and both of its sides.
// before:
@KeyringTest(feature = "aws-kms")
void emptyKeyIdFails(Mpl mpl) {
    mpl.awsKmsKeyring().kmsKeyId("").kmsClient(kms).createFailsWith(INVALID_CONFIGURATION_ERROR);
}
// after:
@KeyringTest(feature = "aws-kms", name = "the KMS key ID must not be empty {0}")
void kmsKeyIdMustNotBeEmpty(Mpl mpl, MockKms mockKms) {
    //= spec/framework/aws-kms/aws-kms-keyring.md#initialization
    //= type=test
    //# The AWS KMS key identifier MUST NOT be null or empty.

    // not empty: succeeds
    mockKms.allowOneEncryptAndDecrypt(KMS_KEY_ARN);
    mpl.awsKmsKeyring()
        .kmsKeyId(KMS_KEY_ARN)
        .kmsClient(mockKms.client())
        .create()
        .assertEncryptsAndDecrypts();

    // empty: fails
    mpl.awsKmsKeyring()
        .kmsKeyId("")
        .kmsClient(mockKms.client())
        .createFailsWith(INVALID_CONFIGURATION_ERROR);
}
```

## Say each side in the spec's words

- Each side gets one comment: `// <scenario>: succeeds` or `// <scenario>: fails`.
- Use only words from the `//#` quote, so a reader can match the side to the rule.
- Name the exact thing, never "the call", "the reply" or "first". A reader should not need the code to know what the comment means.

```java
// name the side with the quote's words.
// before:
// bad reply from KMS
// after:
// Generate Data Key response `KeyId` is not a valid AWS KMS key ARN: fails
```

```java
// name the call, not "the call".
// before:
// the call does not succeed: fails
// after:
// GenerateDataKey call does not succeed: fails
```

## A MAY rule also tests the "not provided" side

- A MAY rule has no failing side.
  Its two sides are "provided" and "not provided", and both succeed.

```java
// test the MAY rule without the optional input too.
// before:
// a list of Grant Tokens provided: succeeds
mpl.awsKmsKeyring()
    .kmsKeyId(KMS_KEY_ARN)
    .kmsClient(mockKms.client())
    .grantTokens(grantTokens.value())
    .create()
    .assertEncryptsAndDecrypts();
// after:
// a list of Grant Tokens provided: succeeds
mpl.awsKmsKeyring()
    .kmsKeyId(KMS_KEY_ARN)
    .kmsClient(mockKms.client())
    .grantTokens(grantTokens.value())
    .create()
    .assertEncryptsAndDecrypts();

// no Grant Tokens: succeeds
mpl.awsKmsKeyring()
    .kmsKeyId(KMS_KEY_ARN)
    .kmsClient(mockKms.client())
    .create()
    .assertEncryptsAndDecrypts();
```

## Names say the rule

- The method name and the `name =` of `@KeyringTest` say the rule, not what the code does.

```java
// name the test after the rule.
// before:
void testEmptyKeyId(Mpl mpl)
// after:
@KeyringTest(feature = "aws-kms", name = "the KMS key ID must not be empty {0}")
void kmsKeyIdMustNotBeEmpty(Mpl mpl, MockKms mockKms)
```

## One builder call per line

```java
// put each builder call on its own line.
// before:
mpl.awsKmsKeyring().kmsKeyId(KMS_KEY_ARN).kmsClient(mockKms.client()).create();
// after:
mpl.awsKmsKeyring()
    .kmsKeyId(KMS_KEY_ARN)
    .kmsClient(mockKms.client())
    .create();
```

## `@KeyringTest`, `inputs` and `pairs`

- `@KeyringTest` runs the test once for each language server.
  It skips a language that does not support the test's feature from feature-set.json.
- `feature =` names that feature.
  Leave it out when the class has `@KeyringFeature`.
- `inputs = "methodName"` runs the test once for each item of the list that the static method returns.
  The item comes in as a parameter before the `Mpl`.
- `pairs = true` runs the test for each pair of languages.
  The test takes two `Mpl`s: the first encrypts and the second decrypts.
- A `MockKms` parameter gets a new MockKms, which stops after the test.

```java
// run once per input with inputs =, not a loop.
// before:
void kmsKeyIdMayBeAnyValidIdentifier(Mpl mpl) {
    for (Example<String> kmsKeyId : KmsFixtures.validKmsIdentifiers(KMS_KEY_ARN)) {
        ...
    }
}
// after:
static List<Example<String>> validKmsIdentifiers() {
    return KmsFixtures.validKmsIdentifiers(KMS_KEY_ARN);
}

@KeyringTest(feature = "aws-kms", name = "the KMS key ID may be {0} {1}", inputs = "validKmsIdentifiers")
void kmsKeyIdMayBeAnyValidIdentifier(Example<String> kmsKeyId, Mpl mpl, MockKms mockKms) {
    ...
}
```

A loop runs every input in one test, so the report shows one result and the first failure hides the rest.
With `inputs =`, each input is its own line in the report.

## `Mpl`, `Keyring`, `Cmm` and `MockKms`

- `Mpl` is one language's MPL.
  It builds keyrings and CMMs (`mpl.awsKmsKeyring()...create()`) and new materials (`mpl.newEncryptionMaterials()`).
- `Keyring` and `Cmm` send each call to the same language's server.
  `onEncrypt` must succeed; `onEncryptFailsWith(materials, expectedError)` must fail with that error.
- `MockKms` is a KMS endpoint that answers with the replies the test scripts.
  Script each reply right before the call that uses it, one `next...` call per KMS call.
  Then check what the keyring sent with `mockKms.generateDataKeyCalls()`, `encryptCalls()` and `decryptCalls()`.

```java
// script each KMS reply right before the call that uses it.
// before:
mockKms.nextGenerateDataKeyReturnsDataKeyFor(KMS_KEY_ARN);
mockKms.nextGenerateDataKeyFailsWith(KMS_ERROR_CODE);
keyring.onEncrypt(mpl.newEncryptionMaterials());
keyring.onEncryptFailsWith(mpl.newEncryptionMaterials(), KMS_CALL_FAILED_ERROR);
// after:
// the call succeeds
mockKms.nextGenerateDataKeyReturnsDataKeyFor(KMS_KEY_ARN);
keyring.onEncrypt(mpl.newEncryptionMaterials());

// the call does not succeed: fails
mockKms.nextGenerateDataKeyFailsWith(KMS_ERROR_CODE);
keyring.onEncryptFailsWith(mpl.newEncryptionMaterials(), KMS_CALL_FAILED_ERROR);
```

## `KeyringContract`

- Every keyring test class implements `KeyringContract`.
  It gives the class the tests that every keyring must pass, from keyring-interface.md.
- The class supplies `workingKeyring(mpl)` and `edksThatDontMatch()`.
- Override a contract test only to add the annotation from the keyring's own spec, then call the contract test.
- A keyring that does not follow a contract rule overrides the test with an empty body and `@ContractException(reason = "...")`.

```java
// add the keyring's own annotation to a contract test.
// before:
// (no override: the test cites only keyring-interface.md)
// after:
@Override
@KeyringTest
public void rejectsDecryptionMaterialsThatHaveADataKey(Mpl mpl) {
    //= spec/framework/aws-kms/aws-kms-keyring.md#ondecrypt
    //= type=test
    //# If the [decryption materials](../structures.md#decryption-materials) already contained a valid plaintext data key
    //# OnDecrypt MUST return an error.
    KeyringContract.super.rejectsDecryptionMaterialsThatHaveADataKey(mpl);
}
```

## `KmsFixtures` and `KmsFuzzRules`

- `KmsFixtures` (in test-server-common/tests-support) has lists of valid and invalid KMS inputs, each with a name.
  Pass them to a test with `inputs =`.
- `KmsFuzzRules` makes random examples for each `KmsFixtures` list of the same name.
  They are added only when `TESTSERVER_FUZZ` is set, such as on the daily fuzz run.
- A new list in `KmsFixtures` gets a rule in `KmsFuzzRules`, so the fuzz run covers it too.

```java
// take shared KMS inputs from KmsFixtures.
// before:
static List<String> badKeyIds() {
    return List.of("", "arn:aws:kms:us-west-2::key/x");
}
// after:
static List<Example<String>> invalidKmsIdentifiers() {
    return KmsFixtures.invalidKmsIdentifiers(KMS_KEY_ARN);
}
```

## Name inputs, don't explain them in comments

- An input's name goes in the code: an `Example` name, a named constant, or a `Materials` helper.
- The same bytes always mean the same thing, so a reader can tell which value is which.

```java
// name a filler value by its role.
// before:
byte[] dataKey = bytes(DATA_KEY_LENGTH, 3); // the data key in the materials
// after:
byte[] dataKey = SOME_DATA_KEY;
```

## Domain assertions

- `KeyringAssertions.assertThat(...)` checks what keyring tests check again and again:
  the data key and EDKs in materials, one EDK's fields, and the requests that MockKms got.
- Its failure messages say what was expected in plain words.
- Keep a plain `assertEquals` for a check that only one test makes.

```java
// check materials, EDKs and KMS requests with KeyringAssertions.
// before:
assertEquals(1, mockKms.encryptCalls().size());
assertEquals(KMS_KEY_ARN, mockKms.encryptCalls().get(0).text("KeyId"));
assertArrayEquals(ciphertext, bytes(edk.getCiphertext()));
// after:
assertThat(mockKms.encryptCalls()).onlyOneCall().sentKeyId(KMS_KEY_ARN);
assertThat(edk).hasCiphertext(ciphertext);
```

## Tag tests that call real KMS

- Put `@UsesRealKms` on each test that makes a call that reaches real KMS, or on the class when all of its tests do.
  It adds the JUnit tag `real-kms`.
- These tests need AWS credentials, and a run can pick or leave them out by that tag.
- A side that fails when the keyring is created never calls KMS.
  Give it `mockKms.client()`, not a real KMS client, and do not tag the test for it.

```java
// tag a test that calls real KMS.
// before:
@KeyringTest(feature = "aws-kms", name = "Decrypt uses the configured client {0}")
void decryptUsesConfiguredClient(Mpl mpl)
// after:
@UsesRealKms
@KeyringTest(feature = "aws-kms", name = "Decrypt uses the configured client {0}")
void decryptUsesConfiguredClient(Mpl mpl)
```

## Flat layout

- Keep tests as methods of the class, grouped under comment headers such as `// OnDecrypt`.
- Use `@Nested` only when a group of tests shares setup that the others don't.

```java
// group tests with a comment header, not @Nested.
// before:
@Nested
class OnDecrypt {
    @KeyringTest void decryptRequest(Mpl mpl, MockKms mockKms) { ... }
}
// after:
// -----------------------------------------------------------------------
// OnDecrypt
// -----------------------------------------------------------------------

@KeyringTest(feature = "aws-kms", name = "Decrypt request {0}")
void decryptRequest(Mpl mpl, MockKms mockKms) { ... }
```

## Duvet annotations on tests

- Each test annotation is `//= <spec path>#<section>`, `//= type=test`, then the exact quote in `//#` lines.
- Copy the quote from the spec; never reword it.
- A language's duvet report credits a test's annotations only when that test runs for the language.

```java
// cite the spec with the exact quote.
// before:
// tests that the key ID is required
// after:
//= spec/framework/aws-kms/aws-kms-keyring.md#initialization
//= type=test
//# - MUST provide an AWS KMS key identifier
```

## Known bugs

- When a language breaks a check, mark it with `.unlessKnownBug("<bug id>")` after the failing call.
- Define the bug id in config/bug-list.json.
  The language lists the ids that it has in its own bug-config.json.
- For a language with the bug, the check may fail and the test still passes.
  For any other language, the check must pass.

```java
// mark a check that a known bug breaks.
// before:
mpl.awsKmsKeyring()
    .kmsKeyId(KMS_KEY_ARN)
    .createFailsWith(INVALID_CONFIGURATION_ERROR);
// after:
mpl.awsKmsKeyring()
    .kmsKeyId(KMS_KEY_ARN)
    .createFailsWith(INVALID_CONFIGURATION_ERROR)
    .unlessKnownBug("aws-kms-keyring-accepts-missing-kms-client");
```

## What CI checks

- Tests on every language: `.github/workflows/mpl-test-server.yml`; locally `make -C mpl/test-server orchestrate`.
- Error checks: each failing side must fail with its `ExpectedError` (`MplErrors`, `KmsErrors`), and `meta/HandleAndErrorContractTest` checks the two error types; they run with the tests above.
- Line coverage of changed lines: aws-crypto-tools-rust `library_rust_coverage.yml`; locally `cargo llvm-cov --workspace --lcov --output-path lcov.info`.
- Branch coverage of changed lines: `python3 test-server-common/tools/branch_gate.py --base origin/main <lcov>...`.
- Per-test coverage and duvet test reach: `.github/workflows/duvet-test-reach-reusable.yml`; locally `test-server-common/tools/per_test_coverage.py` and `duvet_test_reach.py`.
- Mutation testing of changed lines: `.github/workflows/mutation-rust-reusable.yml`; locally `test-server-common/tools/mutation/mutate.py --changed-since origin/main ...`.
- Duvet credit for these tests: `.github/workflows/test-server-duvet-reusable.yml`; locally `make test-server-duvet` in aws-crypto-tools-rust `mpl/test-server`.
- Fuzz, on daily CI: `.github/workflows/test-server-fuzz.yml`; locally `TESTSERVER_FUZZ=200 make -C mpl/test-server orchestrate`.
