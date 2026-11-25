package aws.cryptography.mpl.testserver.tests;

import java.lang.annotation.ElementType;
import java.lang.annotation.Inherited;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * The features of every {@link KeyringTest} in this test class that does not set {@link KeyringTest#feature()}.
 * This includes the {@link KeyringContract} tests that the class gets from the interface.
 */
@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@Inherited
@interface KeyringFeature {

    /** The features from feature-set.json that every language in the run must support. */
    String[] value();
}
