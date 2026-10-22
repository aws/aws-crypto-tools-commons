package aws.cryptography.esdk.testserver.tests;

import aws.cryptography.testserver.tests.TargetPair;

import aws.cryptography.esdk.testserver.client.client.ESDKTestServerClient;
import aws.cryptography.esdk.testserver.client.model.CreateClientInput;
import aws.cryptography.esdk.testserver.client.model.DecryptInput;
import aws.cryptography.esdk.testserver.client.model.EncryptInput;
import aws.cryptography.esdk.testserver.tests.EsdkClientConfigs.Scenario;
import java.nio.ByteBuffer;
import java.util.Map;

/**
 * The shared blob round-trip: {@code CreateClient} on each endpoint of a pair,
 * {@code Encrypt} the plaintext against the encrypt endpoint, then {@code Decrypt}
 * the resulting ciphertext against the decrypt endpoint, and return the recovered
 * plaintext (Requirements 4.2, 4.3, 4.4). Exercises the Blob_Variant only, over
 * the real wire protocol via the ONE generated Java Test_Client.
 *
 * <p>Both the per-configuration {@code MaterialsRoundTripTests#blobRoundTrip}
 * (one named execution per scenario) and the property-based Test (Property 1)
 * drive this single body, so there is exactly one definition of the round trip.
 *
 * <p>Each RPC goes through {@link TestServerClients#withRetry} so a transient
 * transport failure is retried on the test side rather than failing the run.
 */
public final class BlobRoundTrip {

    private BlobRoundTrip() {
    }

    /**
     * Encrypt {@code plaintext} against the pair's encrypt endpoint and decrypt the
     * ciphertext against its decrypt endpoint, returning the recovered plaintext.
     */
    public static byte[] run(TargetPair pair, byte[] plaintext) {
        ESDKTestServerClient encryptClient = TestServerClients.forEndpoint(pair.encryptEndpoint());
        ESDKTestServerClient decryptClient = TestServerClients.forEndpoint(pair.decryptEndpoint());

        // CreateClient on each endpoint; each returns a ClientId referencing a
        // configured, offline Raw-AES ESDK client (Requirement 3.1).
        String encryptClientId = TestServerClients.withRetry(() -> encryptClient.createClient(
            CreateClientInput.builder().config(EsdkClientConfigs.rawAes()).build())).getClientId();
        String decryptClientId = TestServerClients.withRetry(() -> decryptClient.createClient(
            CreateClientInput.builder().config(EsdkClientConfigs.rawAes()).build())).getClientId();

        // Encrypt against one endpoint (Blob_Variant, Requirement 4.2).
        EncryptInput encryptRequest = EncryptInput.builder()
            .clientId(encryptClientId)
            .plaintext(ByteBuffer.wrap(plaintext))
            .build();
        ByteBuffer ciphertext = TestServerClients.withRetry(() -> encryptClient.encrypt(encryptRequest))
            .getCiphertext();

        // Decrypt against the other endpoint (Blob_Variant, Requirement 4.3).
        DecryptInput decryptRequest = DecryptInput.builder()
            .clientId(decryptClientId)
            .ciphertext(ciphertext)
            .build();
        ByteBuffer recovered = TestServerClients.withRetry(() -> decryptClient.decrypt(decryptRequest))
            .getPlaintext();

        return toArray(recovered);
    }

    /**
     * Broadened blob round-trip (Task 14.3): the same single body as {@link
     * #run(TargetPair, byte[])}, but driven by an offline {@link Scenario}
     * (arbitrary supported keyring/CMM/algorithm-suite combination) and an
     * encryption context. The scenario's {@code config} builds the encrypt client
     * and {@link Scenario#decryptConfigOrDefault()} builds the decrypt client
     * (usually the same config, but distinct for the {@code AwsKmsDiscovery}
     * scenario), so the material is compatible and {@code decrypt(encrypt(x)) == x}
     * holds byte-for-byte (Requirements 4.2, 4.3, 4.4).
     *
     * <p>The {@code encryptionContext} is applied on encrypt and supplied again on
     * decrypt (so a Required-Encryption-Context CMM can reconstruct its required
     * keys); the scenario's optional algorithm-suite override is applied on encrypt
     * only (decrypt derives the suite from the message header).
     */
    public static byte[] run(TargetPair pair, byte[] plaintext, Scenario scenario,
                             Map<String, String> encryptionContext) {
        ESDKTestServerClient encryptClient = TestServerClients.forEndpoint(pair.encryptEndpoint());
        ESDKTestServerClient decryptClient = TestServerClients.forEndpoint(pair.decryptEndpoint());

        String encryptClientId = TestServerClients.withRetry(() -> encryptClient.createClient(
            CreateClientInput.builder().config(scenario.config()).build())).getClientId();
        String decryptClientId = TestServerClients.withRetry(() -> decryptClient.createClient(
            CreateClientInput.builder().config(scenario.decryptConfigOrDefault()).build()))
            .getClientId();

        EncryptInput.Builder encryptInput = EncryptInput.builder()
            .clientId(encryptClientId)
            .plaintext(ByteBuffer.wrap(plaintext));
        if (!encryptionContext.isEmpty()) {
            encryptInput.encryptionContext(encryptionContext);
        }
        if (scenario.algorithmSuiteId() != null) {
            encryptInput.algorithmSuiteId(scenario.algorithmSuiteId());
        }
        EncryptInput encryptRequest = encryptInput.build();
        ByteBuffer ciphertext = TestServerClients.withRetry(() -> encryptClient.encrypt(encryptRequest))
            .getCiphertext();

        DecryptInput.Builder decryptInput = DecryptInput.builder()
            .clientId(decryptClientId)
            .ciphertext(ciphertext);
        if (!encryptionContext.isEmpty()) {
            decryptInput.encryptionContext(encryptionContext);
        }
        DecryptInput decryptRequest = decryptInput.build();
        ByteBuffer recovered = TestServerClients.withRetry(() -> decryptClient.decrypt(decryptRequest))
            .getPlaintext();

        return toArray(recovered);
    }

    private static byte[] toArray(ByteBuffer buffer) {
        ByteBuffer duplicate = buffer.duplicate();
        byte[] bytes = new byte[duplicate.remaining()];
        duplicate.get(bytes);
        return bytes;
    }
}
