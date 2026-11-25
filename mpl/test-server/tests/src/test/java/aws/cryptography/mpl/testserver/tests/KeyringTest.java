package aws.cryptography.mpl.testserver.tests;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import org.junit.jupiter.api.TestTemplate;
import org.junit.jupiter.api.extension.ExtendWith;

/**
 * A keyring test that runs once for each language server.
 *
 * <p>Each language has a small server that receives MPL calls over HTTP and passes them to that language's MPL.
 * Before each run, {@link KeyringTestExtension} skips the run if the language does not support {@link #feature()}.
 * Then it gives the test an {@link Mpl} that sends calls to that language's server:
 *
 * <pre>{@code
 * @KeyringTest(feature = "raw-aes", name = "[raw-aes] OnEncrypt makes a data key {0}")
 * void onEncryptMakesDataKey(Mpl mpl) {
 *     Keyring keyring = mpl.rawAesKeyring().keyNamespace("ns").keyName("name")
 *         .wrappingKey(key).wrappingAlg(AesWrappingAlg.ALG_AES256_GCM_IV12_TAG16).create();
 *     keyring.assertEncryptsAndDecrypts();
 * }
 * }</pre>
 *
 * <p>A test with {@link #inputs()} runs once for each input and language server.
 * It takes the input as a parameter next to the {@code Mpl}.
 * A test with {@link #pairs()} takes two {@code Mpl}s: the first language encrypts and the second decrypts.
 */
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
@TestTemplate
@ExtendWith(KeyringTestExtension.class)
@interface KeyringTest {

    /**
     * The features from feature-set.json that every language in the run must support.
     * When empty, the features come from the {@link KeyringFeature} of the test class.
     */
    String[] feature() default {};

    /**
     * The name of each run in the test report, such as {@code "[aws-kms] Decrypt request {0}"}.
     * Without {@link #inputs()}, {@code {0}} is the language server.
     * With {@link #inputs()}, {@code {0}} is the input and {@code {1}} is the language server.
     * The report reads the language server from the end of the name, so put it last.
     * When empty, the name is the feature, the method name and the language server.
     */
    String name() default "";

    /**
     * The name of a static method in the test class that returns a {@code List} of inputs.
     * When empty, the test has no input.
     */
    String inputs() default "";

    /**
     * When true, the test runs once for each pair of language servers, including a language paired with itself.
     * It takes an encrypting {@code Mpl}, then a decrypting {@code Mpl}.
     */
    boolean pairs() default false;
}
