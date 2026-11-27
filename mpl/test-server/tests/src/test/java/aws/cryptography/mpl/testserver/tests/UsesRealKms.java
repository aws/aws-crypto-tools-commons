package aws.cryptography.mpl.testserver.tests;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import org.junit.jupiter.api.Tag;

/**
 * Tags a test, or every test in a class, with the JUnit tag {@code real-kms}.
 *
 * <p>Put it on each test that makes a call that reaches real KMS, and so needs AWS credentials.
 * A test that only gives a keyring a real KMS client, and fails before any KMS call, does not need it.
 * A Gradle run can then pick or leave out these tests by tag.
 */
@Target({ElementType.TYPE, ElementType.METHOD})
@Retention(RetentionPolicy.RUNTIME)
@Tag("real-kms")
@interface UsesRealKms {
}
