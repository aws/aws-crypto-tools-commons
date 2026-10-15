package aws.cryptography.primitives.testserver.tests;

import aws.cryptography.primitives.testserver.client.client.PrimitivesTestServerClient;
import aws.cryptography.primitives.testserver.client.model.DigestAlgorithm;
import aws.cryptography.primitives.testserver.client.model.KbkdfCtrHmacInput;
import aws.cryptography.testserver.tests.FeatureGate;
import aws.cryptography.testserver.tests.LanguageServerRegistry;
import aws.cryptography.testserver.tests.LanguageServerTarget;
import java.util.List;
import java.util.Set;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

/**
 * KBKDF in counter mode with HMAC (NIST SP 800-108 section 4.1, 32-bit
 * big-endian counter before the fixed info) known answers, per target.
 *
 * <p>The vectors are the raw-derive set B.1-B.10 in the Dafny primitives'
 * TestKDF_TestVectors.dfy, where {@code info} is the complete fixed input, which
 * is what the model's {@code info} carries. That file's purpose/nonce set
 * (C.1-C.5) goes through KdfCounterMode, which builds the fixed input itself;
 * the model has no such operation, so those are not ported.
 */
public class KbkdfCtrHmacTest {

    record Vector(String name, DigestAlgorithm algorithm, String ikm, String info, int length,
            String okm) {
        @Override
        public String toString() {
            return name;
        }
    }

    static final List<Vector> VECTORS = List.of(
        new Vector("B.1", DigestAlgorithm.SHA_256,
            "e204d6d466aad507ffaf6d6dab0a5b26152c9e21e764370464e360c8fbc765c6",
            "7b03b98d9f94b899e591f3ef264b71b193fba7043c7e953cde23bc5384bc1a62"
                + "93580115fae3495fd845dadbd02bd6455cf48d0f62b33e62364a3a80",
            32,
            "770dfab6a6a4a4bee0257ff335213f78d8287b4fd537d5c1fffa956910e7c779"),
        new Vector("B.2", DigestAlgorithm.SHA_256,
            "aeeeca60f689a441b13b0cbcd441d82df0cf87dac236290dece8931df8d70317",
            "588ec041e5733b7031212c5538efe4f6aafa4cda8b925d261f5a2688f007b3ac"
                + "240ee12991e77b8cb8538678615966164a81872bd1cfcbfb39a4f450",
            32,
            "3e81d6113cee3c529ecedff89a6999ce25b618c15ee1d19d45cb376a1c8e2374"),
        new Vector("B.3", DigestAlgorithm.SHA_256,
            "95c8f76e11367eb55526a2b393ae906583d1cbdd47962146f506cc7cac12f464",
            "cad60e904b9e9c8bfeb4a81a7f67d3bddcc05e64255870403770f3533ae6dd63"
                + "4ceaa56c53e688bd137ae6018935f34b9fb084ea48e4c688f6bbb388",
            32,
            "cafa5ca03f5fbe2a242004abcbd3de1059c7407b1ee579255124af189be0b556"),
        new Vector("B.4", DigestAlgorithm.SHA_256,
            "4d05391fd6fb1e292e78ab9619b1b72a7d63ee59d7435dd71897b9ff7ee7ae70",
            "f078e6f9b7f82d64554fa6b604c808f19b1f6ad6727db7aa6f1c86694e104b52"
                + "56c8b4039919646481d7ea2452c72c17a3e8d7d3916285460aa5eb81",
            32,
            "6b16e8f53b831aa5e86bf97a5c4fa37d089bc172da5a1e7f662dd4a595339ab7"),
        new Vector("B.5", DigestAlgorithm.SHA_256,
            "0f68a82ff1671634cc9136c564a9e02a767621dd74a1bf5c24129b808214b752",
            "648599809c2c4e7c6a5e6c449f0031ebf55c3661a895b44db0572ee88083b1f4"
                + "b12602aa55fc1df150a65a6d6eeda0aa79a434a1039b91b5a58fc7f1",
            32,
            "e297640f7768485d4a6e7cfe245f8bfa84700d99762692ea1a425ccc0275e8f5"),
        new Vector("B.6", DigestAlgorithm.SHA_384,
            "822c764a1b117085c10f0e689814d2bfbd9b43287f1a8c75d795a9831a286184"
                + "c8586f3577b6e5bbce1637925e04fc47",
            "af346110b941b11d2189316c9fc2b9f4213775a5d7368d35412678a28fcd03b0"
                + "7f0549666efdf30c80f0ab5563720a56ef616a13bb8f7780036fc08e",
            32,
            "e0ae235cb82380527be76934a69622396d90e7bfa7e2d295e4375bcee0d1b101"),
        new Vector("B.7", DigestAlgorithm.SHA_384,
            "340e212d758e83cc5b89e4b56a86ee8c9631ae4e4bbaec15ac095ea4407bc7b6"
                + "34ad630dd0be85a91c08a8c7e1e1030b",
            "3cd5561ad12fadfce408e04180afcee38b83156b9e4be0779c4f0db9e26bfe5c"
                + "cd43e15921977cd26b1db8288b80089eb7d1bbd7f59e1011b3e18b51",
            32,
            "05fa577b7081210e7c9de69db03d7c2026cf4469a90bfa29f1c2c10818d463e0"),
        new Vector("B.8", DigestAlgorithm.SHA_384,
            "00a12d3ce4ff75a6e30f41f3557c826af1326b6302f4ce887bad3d3317a548c8"
                + "c03a057284dcc38d8bc690bd4a565f47",
            "24c5c0b2c810dfa08e35d7feebb8c78e0cd726c92ecd42d9171013738ca2531a"
                + "947f523c37f64cdb04305bd969d1d6f9ecd46405d28280f968500ba7",
            32,
            "aef3d57c8da7d9582c5d1c62d6b64896da9b1b0e4012a44cdc3dcf4b70ad6c66"),
        new Vector("B.9", DigestAlgorithm.SHA_384,
            "0000d9b7ec6fbefdf256fd68220b5205ac65a2001145118c50ba6b657032198b"
                + "8b7ce3b2f7068a780dc17c22459af2b7",
            "d857541c62b85756dc73de7dc2d86f5d5e8b28338bb0a945b5c4fd7c81f71961"
                + "b9705d3d153b19195d003b74212068ed10f96c53438653087a0152cf",
            20,
            "793ef113f96397ab0031eaa0faa777c107e7d03c"),
        new Vector("B.10", DigestAlgorithm.SHA_384,
            "4f3d744d3e449e0627bf4498743828f86e638f60620a7ed4a7c9b5b073691c9e"
                + "c94728c58822e827f0f6ccf86dbc1cae",
            "301feeb25e6ca8503ecd821f1d3787aebfb3d0ec518bb31174f5209b2ac1f28e"
                + "d3e698736bad10a18e3cbdb5dc27bbd12d058b36db0892f9cfd08300",
            20,
            "85ef9505b230565eccf2a64ab3de53e5a91c7b51"));

    static Stream<Arguments> cases() {
        return LanguageServerRegistry.shared().targets().stream()
            .flatMap(target -> VECTORS.stream().map(vector -> Arguments.of(vector, target)));
    }

    @ParameterizedTest(name = "[kbkdf-ctr-hmac] {0} {1}")
    @MethodSource("cases")
    void knownAnswer(Vector vector, LanguageServerTarget target) {
        FeatureGate.require(Set.of("kbkdf-ctr-hmac"), target);
        PrimitivesTestServerClient client = PrimitivesTestServerClients.forEndpoint(target.endpoint());

        byte[] okm = Bytes.of(PrimitivesTestServerClients.withRetry(() ->
            client.kbkdfCtrHmac(KbkdfCtrHmacInput.builder()
                .algorithm(vector.algorithm())
                .ikm(Bytes.buf(vector.ikm()))
                .info(Bytes.buf(vector.info()))
                .expectedLength(vector.length())
                .build())).getOkm());

        assertArrayEquals(Bytes.hex(vector.okm()), okm);
    }
}
