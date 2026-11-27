package aws.cryptography.testserver.tests;

/** The parts of {@code arn:<partition>:kms:<Region>:<account>:key/<key ID>} that the KMS fixtures reuse. */
record KmsKeyArn(String arn, String prefix, String region, String account, String keyId) {

    static KmsKeyArn parse(String keyArn) {
        String[] parts = keyArn.split(":", 6);
        if (parts.length != 6 || !parts[0].equals("arn") || !parts[2].equals("kms")
                || !parts[5].startsWith("key/")) {
            throw new IllegalArgumentException("not a KMS key ARN: " + keyArn);
        }
        String prefix = String.join(":", parts[0], parts[1], parts[2], parts[3], parts[4]) + ":";
        return new KmsKeyArn(keyArn, prefix, parts[3], parts[4], parts[5].substring("key/".length()));
    }
}
