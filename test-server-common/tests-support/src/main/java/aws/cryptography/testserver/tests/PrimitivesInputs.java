package aws.cryptography.testserver.tests;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.Random;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Inputs for the cryptographic primitives that any test can reuse, such as the Primitives test server's tests.
 * Every byte value is lowercase hex, and every algorithm is its name in the test server model, such as {@code SHA_256}.
 *
 * <p>The fixed examples are published test vectors.
 * Each random example's expected output comes from the JDK, so a server that disagrees with the JDK fails.
 * The self-test checks this JDK code against the published vectors.
 *
 * <p>A normal run tests only the fixed examples. {@link Fuzz} says how to add random ones.
 */
public final class PrimitivesInputs {

    private static final HexFormat HEX = HexFormat.of();
    private static final List<String> DIGEST_ALGORITHMS = List.of("SHA_256", "SHA_384", "SHA_512");
    /** The test server model allows only these HKDF output lengths. */
    private static final List<Integer> HKDF_LENGTHS = List.of(16, 24, 32);
    /** The Dafny primitives' KBKDF needs at least 32 bytes of input key material. */
    private static final int MIN_KBKDF_IKM_LENGTH = 32;

    /** "asdf", the message in the Dafny primitives' digest and HMAC tests. */
    private static final String ASDF = "61736466";
    /** "abc", the message in FIPS 180-2's examples. */
    private static final String ABC = "616263";
    private static final String AES_ROUND_TRIP_AAD = utf8Hex("test-aad");

    private PrimitivesInputs() {
    }

    /**
     * An AES-GCM plaintext and its additional authenticated data (AAD).
     * GCM works in 16-byte blocks, so the interesting lengths are near multiples of 16.
     */
    public record AesGcmMessage(String plaintext, String aad) {
    }

    /** A digest input and its expected digest. */
    public record DigestVector(String algorithm, String data, String digest) {
    }

    /** An HMAC key and message and their expected HMAC. */
    public record HmacVector(String algorithm, String key, String message, String digest) {
    }

    /** RFC 5869 HKDF inputs and the expected output key material of {@code length} bytes. */
    public record HkdfVector(String algorithm, String ikm, String salt, String info, int length, String okm) {
    }

    /**
     * KBKDF in counter mode with HMAC (NIST SP 800-108 section 4.1) inputs, and the expected output key material.
     * The {@code info} is the complete fixed input, which follows a 32-bit big-endian counter in each HMAC input.
     */
    public record KbkdfVector(String algorithm, String ikm, String info, int length, String okm) {
    }

    /** Plaintexts and AADs of every length near a 16-byte block, plus a large plaintext. */
    public static List<Example<AesGcmMessage>> aesGcmMessages() {
        return aesGcmMessages(Fuzz.configured());
    }

    static List<Example<AesGcmMessage>> aesGcmMessages(Fuzz fuzz) {
        List<Example<AesGcmMessage>> examples = new ArrayList<>(List.of(
            new Example<>("28-byte plaintext",
                new AesGcmMessage(utf8Hex("hello primitives test-server"), AES_ROUND_TRIP_AAD)),
            new Example<>("empty plaintext and AAD", new AesGcmMessage("", "")),
            new Example<>("1-byte plaintext", new AesGcmMessage(counting(1), AES_ROUND_TRIP_AAD)),
            new Example<>("15-byte plaintext", new AesGcmMessage(counting(15), AES_ROUND_TRIP_AAD)),
            new Example<>("16-byte plaintext", new AesGcmMessage(counting(16), AES_ROUND_TRIP_AAD)),
            new Example<>("17-byte plaintext", new AesGcmMessage(counting(17), AES_ROUND_TRIP_AAD)),
            new Example<>("4096-byte plaintext", new AesGcmMessage(counting(4096), AES_ROUND_TRIP_AAD)),
            new Example<>("17-byte AAD", new AesGcmMessage(counting(16), counting(17)))));
        examples.addAll(fuzz.examples("aesGcmMessages", random -> {
            int plaintextLength = length(random, 2048, 0, 1, 15, 16, 17, 31, 32, 33);
            int aadLength = length(random, 256, 0, 1, 15, 16, 17);
            return new Example<>(plaintextLength + "-byte plaintext, " + aadLength + "-byte AAD",
                new AesGcmMessage(bytes(random, plaintextLength), bytes(random, aadLength)));
        }));
        return examples;
    }

    /** SHA-2 digests. The random messages are often one byte either side of where SHA-2 padding needs another block. */
    public static List<Example<DigestVector>> digestVectors() {
        return digestVectors(Fuzz.configured());
    }

    static List<Example<DigestVector>> digestVectors(Fuzz fuzz) {
        List<Example<DigestVector>> examples = new ArrayList<>(List.of(
            // From the Dafny primitives' TestDigest.dfy.
            new Example<>("SHA-256 asdf", new DigestVector("SHA_256", ASDF,
                "f0e4c2f76c58916ec258f246851bea091d14d4247a2fc3e18694461b1816e13b")),
            new Example<>("SHA-384 asdf", new DigestVector("SHA_384", ASDF,
                "a69e7df30b24c042ec540ccbbdbfb1562c85787038c885749c1e408e2d62fa36"
                    + "642cd0075fa351e822e2b8a59139cd9d")),
            new Example<>("SHA-512 asdf", new DigestVector("SHA_512", ASDF,
                "401b09eab3c013d4ca54922bb802bec8fd5318192b0a75f201d8b3727429080f"
                    + "b337591abd3e44453b954555b7a0812e1081c39b740293f765eae731f5a65ed1")),
            // From FIPS 180-2.
            new Example<>("SHA-256 abc", new DigestVector("SHA_256", ABC,
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")),
            new Example<>("SHA-384 abc", new DigestVector("SHA_384", ABC,
                "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed"
                    + "8086072ba1e7cc2358baeca134c825a7")),
            new Example<>("SHA-512 abc", new DigestVector("SHA_512", ABC,
                "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
                    + "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"))));
        examples.addAll(fuzz.examples("digestVectors", random -> {
            String algorithm = algorithm(random);
            // SHA-256 pads in 64-byte blocks and SHA-384 and SHA-512 in 128-byte blocks.
            // A message of 56 or 112 bytes is the shortest that does not leave room for the padding.
            String data = bytes(random, length(random, 1024, 0, 55, 56, 63, 64, 65, 111, 112, 127, 128, 129));
            return new Example<>(algorithm + " of " + data.length() / 2 + " bytes",
                new DigestVector(algorithm, data, HEX.formatHex(digest(algorithm, HEX.parseHex(data)))));
        }));
        return examples;
    }

    /**
     * HMACs. The random keys are often near the hash's block size, the length above which HMAC hashes the key first.
     * Every key is at least 1 byte, because the JDK's HMAC refuses an empty key.
     */
    public static List<Example<HmacVector>> hmacVectors() {
        return hmacVectors(Fuzz.configured());
    }

    static List<Example<HmacVector>> hmacVectors(Fuzz fuzz) {
        List<Example<HmacVector>> examples = new ArrayList<>(List.of(
            // From the Dafny primitives' TestHMAC.dfy.
            new Example<>("SHA-256 key 01010101", new HmacVector("SHA_256", "01010101", ASDF,
                "5d0c56917befa948c3e2ccb3675ec3538680e2b9b8cb62647320072cac0b5110")),
            new Example<>("SHA-384 key 01010101", new HmacVector("SHA_384", "01010101", ASDF,
                "db2c333cd939bad0084573b9be888801458f9794074295c110e133555cb08bf9"
                    + "385dbd0b9615873699254c44464d9a7c")),
            new Example<>("SHA-512 key 01010101", new HmacVector("SHA_512", "01010101", ASDF,
                "31d515db17a9c327b1010fa2e9b6d054e2031b784b4e552edc05a6ce4f2f195e"
                    + "5877d3c09417fc9b62da61e1265d53718b5f65de9a62f4ce58e50673e2bc98ad")),
            // From the Dafny primitives' TestAwsCryptographyPrimitivesHMAC.dfy.
            new Example<>("SHA-256 key 01020304", new HmacVector("SHA_256", "01020304", ASDF,
                "376bbaf133ff9aa96a8502f836e6c193d4b39a422b346cb5909813657563cc86")),
            new Example<>("SHA-384 key 01020304", new HmacVector("SHA_384", "01020304", ASDF,
                "5aceea51ad4ceb94cb8bc32efb0e616e92319318f00111e73a68923590a70b70"
                    + "07277a0f3a35905b10df33621e5817a6")),
            new Example<>("SHA-512 key 01020304", new HmacVector("SHA_512", "01020304", ASDF,
                "6417add7274333a595355754913add9befb6f98693bf8fe08ca5beddb70f0666"
                    + "cb4dee400a8a3d40db4ff8f95a66d9bc0d026560d9f249febed98621a38997b7"))));
        examples.addAll(fuzz.examples("hmacVectors", random -> {
            String algorithm = algorithm(random);
            byte[] key = HEX.parseHex(bytes(random, Math.max(1, length(random, 300, 63, 64, 65, 127, 128, 129))));
            byte[] message = HEX.parseHex(bytes(random, length(random, 1024, 0, 1, 64, 128)));
            return new Example<>(algorithm + " with a " + key.length + "-byte key and " + message.length + "-byte message",
                new HmacVector(algorithm, HEX.formatHex(key), HEX.formatHex(message),
                    HEX.formatHex(hmac(algorithm, key, message))));
        }));
        return examples;
    }

    /**
     * HKDF inputs at every output length that the test server model allows.
     * Every salt is at least 1 byte, because the Dafny primitives reject an empty salt.
     */
    public static List<Example<HkdfVector>> hkdfVectors() {
        return hkdfVectors(Fuzz.configured());
    }

    static List<Example<HkdfVector>> hkdfVectors(Fuzz fuzz) {
        // RFC 5869 Appendix A test cases 1 to 3, with the first 32 bytes of each one's output key material.
        // HKDF output does not depend on the length asked for, so a shorter output is a prefix of the RFC's.
        List<String[]> rfcCases = List.of(
            new String[] {"RFC 5869 A.1",
                "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
                "000102030405060708090a0b0c",
                "f0f1f2f3f4f5f6f7f8f9",
                "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"},
            new String[] {"RFC 5869 A.2",
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
                    + "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
                    + "404142434445464748494a4b4c4d4e4f",
                "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f"
                    + "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"
                    + "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf",
                "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecf"
                    + "d0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeef"
                    + "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
                "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c"},
            // No salt and empty info. The Dafny primitives reject a present but empty salt,
            // so "no salt" is sent as RFC 5869 section 2.2's default: HashLen (32) zero bytes.
            // HMAC pads a short key with zeros, so this gives the same output as an empty salt.
            new String[] {"RFC 5869 A.3",
                "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
                "0000000000000000000000000000000000000000000000000000000000000000",
                "",
                "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d"});
        List<Example<HkdfVector>> examples = new ArrayList<>();
        for (String[] rfcCase : rfcCases) {
            for (int length : HKDF_LENGTHS) {
                examples.add(new Example<>(rfcCase[0] + " L=" + length, new HkdfVector("SHA_256",
                    rfcCase[1], rfcCase[2], rfcCase[3], length, rfcCase[4].substring(0, 2 * length))));
            }
        }
        examples.addAll(fuzz.examples("hkdfVectors", random -> {
            String algorithm = algorithm(random);
            byte[] ikm = HEX.parseHex(bytes(random, 1 + random.nextInt(100)));
            byte[] salt = HEX.parseHex(bytes(random, 1 + random.nextInt(100)));
            byte[] info = HEX.parseHex(bytes(random, random.nextInt(100)));
            int length = HKDF_LENGTHS.get(random.nextInt(HKDF_LENGTHS.size()));
            return new Example<>(algorithm + " L=" + length + " from a " + ikm.length + "-byte IKM",
                new HkdfVector(algorithm, HEX.formatHex(ikm), HEX.formatHex(salt), HEX.formatHex(info), length,
                    HEX.formatHex(hkdf(algorithm, salt, ikm, info, length))));
        }));
        return examples;
    }

    /** KBKDF inputs. The random output lengths are often one byte either side of a whole number of HMAC outputs. */
    public static List<Example<KbkdfVector>> kbkdfVectors() {
        return kbkdfVectors(Fuzz.configured());
    }

    static List<Example<KbkdfVector>> kbkdfVectors(Fuzz fuzz) {
        // The raw-derive set B.1 to B.10 in the Dafny primitives' TestKDF_TestVectors.dfy.
        List<Example<KbkdfVector>> examples = new ArrayList<>(List.of(
            new Example<>("B.1", new KbkdfVector("SHA_256",
                "e204d6d466aad507ffaf6d6dab0a5b26152c9e21e764370464e360c8fbc765c6",
                "7b03b98d9f94b899e591f3ef264b71b193fba7043c7e953cde23bc5384bc1a62"
                    + "93580115fae3495fd845dadbd02bd6455cf48d0f62b33e62364a3a80",
                32,
                "770dfab6a6a4a4bee0257ff335213f78d8287b4fd537d5c1fffa956910e7c779")),
            new Example<>("B.2", new KbkdfVector("SHA_256",
                "aeeeca60f689a441b13b0cbcd441d82df0cf87dac236290dece8931df8d70317",
                "588ec041e5733b7031212c5538efe4f6aafa4cda8b925d261f5a2688f007b3ac"
                    + "240ee12991e77b8cb8538678615966164a81872bd1cfcbfb39a4f450",
                32,
                "3e81d6113cee3c529ecedff89a6999ce25b618c15ee1d19d45cb376a1c8e2374")),
            new Example<>("B.3", new KbkdfVector("SHA_256",
                "95c8f76e11367eb55526a2b393ae906583d1cbdd47962146f506cc7cac12f464",
                "cad60e904b9e9c8bfeb4a81a7f67d3bddcc05e64255870403770f3533ae6dd63"
                    + "4ceaa56c53e688bd137ae6018935f34b9fb084ea48e4c688f6bbb388",
                32,
                "cafa5ca03f5fbe2a242004abcbd3de1059c7407b1ee579255124af189be0b556")),
            new Example<>("B.4", new KbkdfVector("SHA_256",
                "4d05391fd6fb1e292e78ab9619b1b72a7d63ee59d7435dd71897b9ff7ee7ae70",
                "f078e6f9b7f82d64554fa6b604c808f19b1f6ad6727db7aa6f1c86694e104b52"
                    + "56c8b4039919646481d7ea2452c72c17a3e8d7d3916285460aa5eb81",
                32,
                "6b16e8f53b831aa5e86bf97a5c4fa37d089bc172da5a1e7f662dd4a595339ab7")),
            new Example<>("B.5", new KbkdfVector("SHA_256",
                "0f68a82ff1671634cc9136c564a9e02a767621dd74a1bf5c24129b808214b752",
                "648599809c2c4e7c6a5e6c449f0031ebf55c3661a895b44db0572ee88083b1f4"
                    + "b12602aa55fc1df150a65a6d6eeda0aa79a434a1039b91b5a58fc7f1",
                32,
                "e297640f7768485d4a6e7cfe245f8bfa84700d99762692ea1a425ccc0275e8f5")),
            new Example<>("B.6", new KbkdfVector("SHA_384",
                "822c764a1b117085c10f0e689814d2bfbd9b43287f1a8c75d795a9831a286184"
                    + "c8586f3577b6e5bbce1637925e04fc47",
                "af346110b941b11d2189316c9fc2b9f4213775a5d7368d35412678a28fcd03b0"
                    + "7f0549666efdf30c80f0ab5563720a56ef616a13bb8f7780036fc08e",
                32,
                "e0ae235cb82380527be76934a69622396d90e7bfa7e2d295e4375bcee0d1b101")),
            new Example<>("B.7", new KbkdfVector("SHA_384",
                "340e212d758e83cc5b89e4b56a86ee8c9631ae4e4bbaec15ac095ea4407bc7b6"
                    + "34ad630dd0be85a91c08a8c7e1e1030b",
                "3cd5561ad12fadfce408e04180afcee38b83156b9e4be0779c4f0db9e26bfe5c"
                    + "cd43e15921977cd26b1db8288b80089eb7d1bbd7f59e1011b3e18b51",
                32,
                "05fa577b7081210e7c9de69db03d7c2026cf4469a90bfa29f1c2c10818d463e0")),
            new Example<>("B.8", new KbkdfVector("SHA_384",
                "00a12d3ce4ff75a6e30f41f3557c826af1326b6302f4ce887bad3d3317a548c8"
                    + "c03a057284dcc38d8bc690bd4a565f47",
                "24c5c0b2c810dfa08e35d7feebb8c78e0cd726c92ecd42d9171013738ca2531a"
                    + "947f523c37f64cdb04305bd969d1d6f9ecd46405d28280f968500ba7",
                32,
                "aef3d57c8da7d9582c5d1c62d6b64896da9b1b0e4012a44cdc3dcf4b70ad6c66")),
            new Example<>("B.9", new KbkdfVector("SHA_384",
                "0000d9b7ec6fbefdf256fd68220b5205ac65a2001145118c50ba6b657032198b"
                    + "8b7ce3b2f7068a780dc17c22459af2b7",
                "d857541c62b85756dc73de7dc2d86f5d5e8b28338bb0a945b5c4fd7c81f71961"
                    + "b9705d3d153b19195d003b74212068ed10f96c53438653087a0152cf",
                20,
                "793ef113f96397ab0031eaa0faa777c107e7d03c")),
            new Example<>("B.10", new KbkdfVector("SHA_384",
                "4f3d744d3e449e0627bf4498743828f86e638f60620a7ed4a7c9b5b073691c9e"
                    + "c94728c58822e827f0f6ccf86dbc1cae",
                "301feeb25e6ca8503ecd821f1d3787aebfb3d0ec518bb31174f5209b2ac1f28e"
                    + "d3e698736bad10a18e3cbdb5dc27bbd12d058b36db0892f9cfd08300",
                20,
                "85ef9505b230565eccf2a64ab3de53e5a91c7b51"))));
        examples.addAll(fuzz.examples("kbkdfVectors", random -> {
            String algorithm = algorithm(random);
            byte[] ikm = HEX.parseHex(bytes(random, MIN_KBKDF_IKM_LENGTH + random.nextInt(49)));
            byte[] info = HEX.parseHex(bytes(random, random.nextInt(100)));
            int length = Math.max(1, length(random, 200, 31, 32, 33, 47, 48, 49, 63, 64, 65));
            return new Example<>(algorithm + " L=" + length + " from a " + ikm.length + "-byte IKM",
                new KbkdfVector(algorithm, HEX.formatHex(ikm), HEX.formatHex(info), length,
                    HEX.formatHex(kbkdf(algorithm, ikm, info, length))));
        }));
        return examples;
    }

    static byte[] digest(String algorithm, byte[] data) {
        try {
            return MessageDigest.getInstance(algorithm.replace('_', '-')).digest(data);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    static byte[] hmac(String algorithm, byte[] key, byte[] message) {
        try {
            String name = "Hmac" + algorithm.replace("_", "");
            Mac mac = Mac.getInstance(name);
            mac.init(new SecretKeySpec(key, name));
            return mac.doFinal(message);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    /** RFC 5869 section 2: extract a pseudorandom key from the salt and IKM, then expand it with the info. */
    static byte[] hkdf(String algorithm, byte[] salt, byte[] ikm, byte[] info, int length) {
        byte[] prk = hmac(algorithm, salt, ikm);
        ByteArrayOutputStream okm = new ByteArrayOutputStream();
        byte[] block = new byte[0];
        for (int i = 1; okm.size() < length; i++) {
            ByteArrayOutputStream input = new ByteArrayOutputStream();
            input.writeBytes(block);
            input.writeBytes(info);
            input.write(i);
            block = hmac(algorithm, prk, input.toByteArray());
            okm.writeBytes(block);
        }
        return Arrays.copyOf(okm.toByteArray(), length);
    }

    /** NIST SP 800-108 section 4.1: HMAC of a 32-bit big-endian counter and the info, until there are enough bytes. */
    static byte[] kbkdf(String algorithm, byte[] ikm, byte[] info, int length) {
        ByteArrayOutputStream okm = new ByteArrayOutputStream();
        for (int i = 1; okm.size() < length; i++) {
            ByteArrayOutputStream input = new ByteArrayOutputStream();
            input.writeBytes(new byte[] {(byte) (i >>> 24), (byte) (i >>> 16), (byte) (i >>> 8), (byte) i});
            input.writeBytes(info);
            okm.writeBytes(hmac(algorithm, ikm, input.toByteArray()));
        }
        return Arrays.copyOf(okm.toByteArray(), length);
    }

    private static String algorithm(Random random) {
        return DIGEST_ALGORITHMS.get(random.nextInt(DIGEST_ALGORITHMS.size()));
    }

    /** Half the time one of the {@code boundaries}, otherwise any length from 0 to {@code max}. */
    private static int length(Random random, int max, int... boundaries) {
        return random.nextBoolean()
            ? boundaries[random.nextInt(boundaries.length)]
            : random.nextInt(max + 1);
    }

    private static String bytes(Random random, int length) {
        byte[] bytes = new byte[length];
        random.nextBytes(bytes);
        return HEX.formatHex(bytes);
    }

    /** {@code length} bytes counting up from 00, wrapping after ff. */
    private static String counting(int length) {
        byte[] bytes = new byte[length];
        for (int i = 0; i < length; i++) {
            bytes[i] = (byte) i;
        }
        return HEX.formatHex(bytes);
    }

    private static String utf8Hex(String text) {
        return HEX.formatHex(text.getBytes(StandardCharsets.UTF_8));
    }
}
