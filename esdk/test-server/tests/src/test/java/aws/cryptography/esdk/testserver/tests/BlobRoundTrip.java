package aws.cryptography.esdk.testserver.tests;

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
 */
public final class BlobRoundTrip {

    private BlobRoundTrip() {
    }

    /**
     * Encrypt {@code plaintext} against the pair's encrypt endpoint and decrypt the
     * ciphertext against its decrypt endpoint, returning the recovered plaintext.
     */
    public static byte[] run(EndpointPair pair, byte[] plaintext) {
        ESDKTestServerClient encryptClient = TestServerClients.forEndpoint(pair.encryptEndpoint());
        ESDKTestServerClient decryptClient = TestServerClients.forEndpoint(pair.decryptEndpoint());

        // CreateClient on each endpoint; each returns a ClientId referencing a
        // configured, offline Raw-AES ESDK client (Requirement 3.1).
        String encryptClientId = encryptClient.createClient(
            CreateClientInput.builder().config(EsdkClientConfigs.rawAes()).build()).getClientId();
        String decryptClientId = decryptClient.createClient(
            CreateClientInput.builder().config(EsdkClientConfigs.rawAes()).build()).getClientId();

        // Encrypt against one endpoint (Blob_Variant, Requirement 4.2).
        ByteBuffer ciphertext = encryptClient.encrypt(
            EncryptInput.builder()
                .clientId(encryptClientId)
                .plaintext(ByteBuffer.wrap(plaintext))
                .build())
            .getCiphertext();

        // Decrypt against the other endpoint (Blob_Variant, Requirement 4.3).
        ByteBuffer recovered = decryptClient.decrypt(
            DecryptInput.builder()
                .clientId(decryptClientId)
                .ciphertext(ciphertext)
                .build())
            .getPlaintext();

        return toArray(recovered);
    }

    /**
     * Broadened blob round-trip (Task 14.3): the same single body as {@link
     * #run(EndpointPair, byte[])}, but driven by an offline {@link Scenario}
     * (arbitrary supported keyring/CMM/algorithm-suite combination) and an
     * encryption context. The scenario's single config builds BOTH the encrypt
     * and decrypt client, so the material is compatible and {@code
     * decrypt(encrypt(x)) == x} holds byte-for-byte (Requirements 4.2, 4.3, 4.4).
     *
     * <p>The {@code encryptionContext} is applied on encrypt and supplied again on
     * decrypt (so a Required-Encryption-Context CMM can reconstruct its required
     * keys); the scenario's optional algorithm-suite override is applied on encrypt
     * only (decrypt derives the suite from the message header).
     */
    public static byte[] run(EndpointPair pair, byte[] plaintext, Scenario scenario,
                             Map<String, String> encryptionContext) {
        ESDKTestServerClient encryptClient = TestServerClients.forEndpoint(pair.encryptEndpoint());
        ESDKTestServerClient decryptClient = TestServerClients.forEndpoint(pair.decryptEndpoint());

        String encryptClientId = encryptClient.createClient(
            CreateClientInput.builder().config(scenario.config()).build()).getClientId();
        String decryptClientId = decryptClient.createClient(
            CreateClientInput.builder().config(scenario.config()).build()).getClientId();

        EncryptInput.Builder encryptInput = EncryptInput.builder()
            .clientId(encryptClientId)
            .plaintext(ByteBuffer.wrap(plaintext));
        if (!encryptionContext.isEmpty()) {
            encryptInput.encryptionContext(encryptionContext);
        }
        if (scenario.algorithmSuiteId() != null) {
            encryptInput.algorithmSuiteId(scenario.algorithmSuiteId());
        }
        ByteBuffer ciphertext = encryptClient.encrypt(encryptInput.build()).getCiphertext();

        DecryptInput.Builder decryptInput = DecryptInput.builder()
            .clientId(decryptClientId)
            .ciphertext(ciphertext);
        if (!encryptionContext.isEmpty()) {
            decryptInput.encryptionContext(encryptionContext);
        }
        ByteBuffer recovered = decryptClient.decrypt(decryptInput.build()).getPlaintext();

        return toArray(recovered);
    }

    private static byte[] toArray(ByteBuffer buffer) {
        ByteBuffer duplicate = buffer.duplicate();
        byte[] bytes = new byte[duplicate.remaining()];
        duplicate.get(bytes);
        return bytes;
    }
}
