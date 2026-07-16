package aws.cryptography.esdk.testserver.tests;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import aws.cryptography.esdk.testserver.client.client.ESDKTestServerClient;
import aws.cryptography.esdk.testserver.client.model.CreateClientInput;
import aws.cryptography.esdk.testserver.client.model.DecryptInput;
import aws.cryptography.esdk.testserver.client.model.ESDKClientError;
import aws.cryptography.esdk.testserver.client.model.EncryptInput;
import aws.cryptography.esdk.testserver.client.model.GenericServerError;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Over-the-wire modeled-error transmission Tests (Task 14.4). Driven by the real
 * Java {@code Test_Client} over the real rpcv2Cbor HTTP hop, these confirm that
 * the TWO modeled error shapes actually transmit and stay <em>distinguishable</em>
 * end-to-end — directly exercising the smithy-java rpcv2-CBOR modeled-error
 * transmission caveat called out in the design's Error Handling section:
 *
 * <ul>
 *   <li>A {@code Decrypt} with wrong/incompatible key material surfaces as an
 *       {@link ESDKClientError} forwarding the ESDK exception message
 *       (Requirements 4.11, 5.6).</li>
 *   <li>A bad/absent/unknown {@code ClientId} surfaces as a
 *       {@link GenericServerError} (Requirements 3.9, 5.5).</li>
 * </ul>
 *
 * <p>These assert the client receives the correct <em>modeled</em> type (not a
 * bare {@code CallException}/HTTP error, Requirements 6.1–6.4) and that the two
 * shapes are distinct — an {@link ESDKClientError} is never a
 * {@link GenericServerError} and vice versa. Fully offline: Raw-AES configs, no
 * AWS/KMS/network.
 *
 * <p>Findings (bring-up over rpcv2Cbor): with smithy-java 1.4.0 the two modeled
 * errors <strong>do</strong> serialize and deserialize distinctly over rpcv2Cbor
 * — the generated Java server encodes each {@code @error("client")} shape with its
 * shape id and the generated client's error deserializer maps it back to the
 * matching modeled type via the operation's type registry. No client/server wiring
 * change was required for the error path (unlike the {@code @streaming} blob
 * transport, which the same codec does not support — see {@link StreamRoundTrip}).
 */
class ModeledErrorTransmissionTest {

    private static final byte[] PLAINTEXT =
        "esdk-test-server modeled-error transmission plaintext".getBytes(StandardCharsets.UTF_8);

    @Test
    @DisplayName("Decrypt with incompatible key material surfaces as ESDKClientError over the wire")
    void wrongKeyMaterialSurfacesAsEsdkClientError() {
        EndpointPair pair = LanguageServerRegistry.shared().selfPair();
        ESDKTestServerClient encryptClient = TestServerClients.forEndpoint(pair.encryptEndpoint());
        ESDKTestServerClient decryptClient = TestServerClients.forEndpoint(pair.decryptEndpoint());

        // Encrypt with one Raw-AES key.
        String encryptClientId = encryptClient.createClient(
            CreateClientInput.builder().config(EsdkClientConfigs.rawAes()).build()).getClientId();
        ByteBuffer ciphertext = encryptClient.encrypt(
            EncryptInput.builder()
                .clientId(encryptClientId)
                .plaintext(ByteBuffer.wrap(PLAINTEXT))
                .build())
            .getCiphertext();

        // Decrypt with a DIFFERENT (incompatible) Raw-AES key: the ESDK cannot
        // unwrap the data key, so the failure originates inside the ESDK_Client
        // and must forward as an ESDKClientError (Requirements 4.11, 5.6).
        String decryptClientId = decryptClient.createClient(
            CreateClientInput.builder().config(EsdkClientConfigs.rawAesIncompatibleKey()).build())
            .getClientId();

        ESDKClientError error = assertThrows(ESDKClientError.class, () ->
            decryptClient.decrypt(DecryptInput.builder()
                .clientId(decryptClientId)
                .ciphertext(ciphertext)
                .build()));

        // The ESDK exception message is forwarded (non-empty), and the shape is
        // distinct from GenericServerError. assertThrows above already proves the
        // wire error deserialized to the EXACT modeled type ESDKClientError (a
        // distinct final class from GenericServerError), not a bare CallException —
        // so the two shapes are distinguishable end-to-end. Also confirm the message.
        assertNotNull(error.getMessage());
        assertFalse(error.getMessage().isEmpty(),
            "ESDKClientError must forward the (non-empty) ESDK exception message");
    }

    @Test
    @DisplayName("Decrypt with an unknown ClientId surfaces as GenericServerError over the wire")
    void unknownClientIdSurfacesAsGenericServerError() {
        EndpointPair pair = LanguageServerRegistry.shared().selfPair();
        ESDKTestServerClient client = TestServerClients.forEndpoint(pair.decryptEndpoint());

        // No CreateClient call: this ClientId is not present in the registry, so
        // the guard rejects it with a GenericServerError before any ESDK call
        // (Requirements 3.9, 5.5), performing no operation.
        GenericServerError error = assertThrows(GenericServerError.class, () ->
            client.decrypt(DecryptInput.builder()
                .clientId("00000000-0000-0000-0000-000000000000")
                .ciphertext(ByteBuffer.wrap(new byte[] {1, 2, 3, 4}))
                .build()));

        // assertThrows above already proves the wire error deserialized to the
        // EXACT modeled type GenericServerError (distinct from ESDKClientError),
        // not a bare CallException.
        assertNotNull(error.getMessage());
        assertFalse(error.getMessage().isEmpty(),
            "GenericServerError must carry a non-empty message");
    }

    @Test
    @DisplayName("Decrypt with an empty ClientId surfaces as GenericServerError over the wire")
    void emptyClientIdSurfacesAsGenericServerError() {
        EndpointPair pair = LanguageServerRegistry.shared().selfPair();
        ESDKTestServerClient client = TestServerClients.forEndpoint(pair.decryptEndpoint());

        GenericServerError error = assertThrows(GenericServerError.class, () ->
            client.decrypt(DecryptInput.builder()
                .clientId("")
                .ciphertext(ByteBuffer.wrap(new byte[] {1, 2, 3, 4}))
                .build()));

        assertNotNull(error.getMessage());
        assertFalse(error.getMessage().isEmpty(),
            "GenericServerError must carry a non-empty message");
    }
}
