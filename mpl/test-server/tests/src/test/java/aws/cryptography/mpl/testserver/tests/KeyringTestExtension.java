package aws.cryptography.mpl.testserver.tests;

import aws.cryptography.testserver.tests.FeatureGate;
import aws.cryptography.testserver.tests.LanguageServerRegistry;
import aws.cryptography.testserver.tests.LanguageServerTarget;
import aws.cryptography.testserver.tests.TargetPair;
import java.lang.reflect.Method;
import java.lang.reflect.Parameter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import java.util.stream.Stream;
import org.junit.jupiter.api.extension.AfterEachCallback;
import org.junit.jupiter.api.extension.BeforeEachCallback;
import org.junit.jupiter.api.extension.Extension;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.api.extension.ParameterContext;
import org.junit.jupiter.api.extension.ParameterResolver;
import org.junit.jupiter.api.extension.TestTemplateInvocationContext;
import org.junit.jupiter.api.extension.TestTemplateInvocationContextProvider;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.platform.commons.support.AnnotationSupport;
import org.junit.platform.commons.support.ReflectionSupport;

/**
 * Runs a {@link KeyringTest} once for each language server, or once for each input and language server.
 *
 * <p>JUnit asks this provider for the runs of a test when it plans the test class.
 * Each run is one {@link Run}, which JUnit also uses as an extension for that run alone:
 * <ol>
 *   <li>Before the test body, {@link Run#beforeEach} skips a test marked {@link ContractException}.
 *       Otherwise it calls {@link FeatureGate#require}.
 *       That call skips the run when a language does not support the feature.
 *       Both skips are recorded in feature-gate-log.jsonl, and so is a run that goes on.
 *       Then it builds the test server client.
 *       In a dry run, building the client stops the run and logs it as one that would run.</li>
 *   <li>{@link Run#resolveParameter} gives the test its {@link Mpl} and its input.
 *       An {@link Arguments} input fills one parameter with each of its arguments, in order.
 *       It also gives a new {@link MockKms} for each {@code MockKms} parameter.</li>
 *   <li>After the test body, {@link Run#afterEach} stops each MockKms.
 *       Then it fails the test if a {@link FailureCheck} failed and the test did not mark it with a known bug.</li>
 * </ol>
 */
final class KeyringTestExtension implements TestTemplateInvocationContextProvider {

    @Override
    public boolean supportsTestTemplate(ExtensionContext context) {
        return AnnotationSupport.isAnnotated(context.getTestMethod(), KeyringTest.class);
    }

    @Override
    public Stream<TestTemplateInvocationContext> provideTestTemplateInvocationContexts(ExtensionContext context) {
        Method testMethod = context.getRequiredTestMethod();
        KeyringTest settings = AnnotationSupport.findAnnotation(testMethod, KeyringTest.class).orElseThrow();
        Set<String> features = features(settings, testMethod, context.getRequiredTestClass());
        List<?> languageServers = settings.pairs()
            ? LanguageServerRegistry.shared().pairs()
            : LanguageServerRegistry.shared().targets();
        List<?> inputs = settings.inputs().isEmpty()
            ? List.of(Run.NO_INPUT)
            : inputs(context.getRequiredTestClass(), settings.inputs());

        // Each input runs on every language server, in the order that a
        // @MethodSource of (input, languageServer) arguments would give.
        List<TestTemplateInvocationContext> runs = new ArrayList<>();
        for (Object input : inputs) {
            for (Object languageServer : languageServers) {
                runs.add(new Run(features, settings, testMethod, input, languageServer));
            }
        }
        return runs.stream();
    }

    /**
     * {@link KeyringTest#feature()}, or else the {@link KeyringFeature} of the test class.
     * The test class is the class that JUnit runs, so a {@link KeyringContract} test gets the features of each keyring.
     */
    private static Set<String> features(KeyringTest settings, Method testMethod, Class<?> testClass) {
        if (settings.feature().length > 0) {
            return Set.copyOf(Arrays.asList(settings.feature()));
        }
        KeyringFeature classFeature = testClass.getAnnotation(KeyringFeature.class);
        if (classFeature == null) {
            throw new IllegalStateException("@KeyringTest " + testClass.getName() + "." + testMethod.getName()
                + " has no feature: set feature, or put @KeyringFeature on the class");
        }
        return Set.copyOf(Arrays.asList(classFeature.value()));
    }

    /** Call the static method named by {@link KeyringTest#inputs()}. */
    private static List<?> inputs(Class<?> testClass, String methodName) {
        Method method = ReflectionSupport.findMethod(testClass, methodName)
            .orElseThrow(() -> new IllegalStateException(
                "@KeyringTest inputs: " + testClass.getName() + " has no method " + methodName + "()"));
        Object inputs = ReflectionSupport.invokeMethod(method, null);
        if (!(inputs instanceof List<?> list)) {
            throw new IllegalStateException(
                "@KeyringTest inputs: " + testClass.getName() + "." + methodName + "() must return a List");
        }
        return list;
    }

    /** One run of a test: one input on one language server, or on one pair of language servers. */
    private static final class Run
            implements TestTemplateInvocationContext, BeforeEachCallback, ParameterResolver, AfterEachCallback {

        /** The input of a test that has no {@link KeyringTest#inputs()}. */
        static final Object NO_INPUT = new Object();

        private final Set<String> features;
        private final KeyringTest settings;
        private final Method testMethod;
        /**
         * The input's values, one for each test parameter that is not an {@code Mpl} or a {@code MockKms}.
         * An {@link Arguments} input gives one value for each of its arguments; any other input is one value.
         */
        private final List<Object> inputValues;
        /** A {@link LanguageServerTarget}, or a {@link TargetPair} for a test with {@link KeyringTest#pairs()}. */
        private final Object languageServer;
        /** One per {@code Mpl} parameter, in parameter order. Set by {@link #beforeEach}. */
        private List<Mpl> mpls;
        /** One per {@code MockKms} parameter. {@link #afterEach} stops them. */
        private final List<MockKms> mockKmses = new ArrayList<>();

        Run(Set<String> features, KeyringTest settings, Method testMethod, Object input, Object languageServer) {
            this.features = features;
            this.settings = settings;
            this.testMethod = testMethod;
            if (input == NO_INPUT) {
                this.inputValues = List.of();
            } else if (input instanceof Arguments arguments) {
                this.inputValues = Arrays.asList(arguments.get());
            } else {
                this.inputValues = List.of(input);
            }
            this.languageServer = languageServer;
        }

        /** Fill the {@link KeyringTest#name()} pattern the same way a {@code @ParameterizedTest} name is. */
        @Override
        public String getDisplayName(int invocationIndex) {
            List<Object> arguments = new ArrayList<>(inputValues);
            arguments.add(languageServer);
            String pattern = settings.name();
            if (pattern.isEmpty()) {
                StringBuilder defaultPattern = new StringBuilder("[" + String.join(", ", new TreeSet<>(features)) + "] "
                    + testMethod.getName());
                for (int i = 0; i < arguments.size(); i++) {
                    defaultPattern.append(" {").append(i).append("}");
                }
                pattern = defaultPattern.toString();
            }
            for (int i = 0; i < arguments.size(); i++) {
                pattern = pattern.replace("{" + i + "}", String.valueOf(arguments.get(i)));
            }
            return pattern;
        }

        @Override
        public List<Extension> getAdditionalExtensions() {
            return List.of(this);
        }

        @Override
        public void beforeEach(ExtensionContext context) {
            ContractException exception = testMethod.getAnnotation(ContractException.class);
            if (exception != null) {
                String message = "keyring contract exception: " + exception.reason();
                if (languageServer instanceof TargetPair pair) {
                    FeatureGate.skip(message, features, pair);
                } else {
                    FeatureGate.skip(message, features, (LanguageServerTarget) languageServer);
                }
            }
            KeyringTestDefaults defaults = context.getRequiredTestInstance() instanceof KeyringTestDefaults d ? d : null;
            if (languageServer instanceof TargetPair pair) {
                FeatureGate.require(features, pair);
                mpls = List.of(
                    new Mpl(pair.encryptTarget(), defaults),
                    new Mpl(pair.decryptTarget(), defaults));
            } else {
                LanguageServerTarget target = (LanguageServerTarget) languageServer;
                FeatureGate.require(features, target);
                mpls = List.of(new Mpl(target, defaults));
            }
        }

        /** An {@code Mpl}, a {@code MockKms}, or a parameter that its input value fits. */
        @Override
        public boolean supportsParameter(ParameterContext parameterContext, ExtensionContext extensionContext) {
            Class<?> type = parameterContext.getParameter().getType();
            if (type == Mpl.class || type == MockKms.class) {
                return true;
            }
            int valueIndex = inputValueIndex(parameterContext.getIndex());
            return valueIndex < inputValues.size()
                && (inputValues.get(valueIndex) == null || boxed(type).isInstance(inputValues.get(valueIndex)));
        }

        @Override
        public Object resolveParameter(ParameterContext parameterContext, ExtensionContext extensionContext) {
            Parameter parameter = parameterContext.getParameter();
            if (parameter.getType() == MockKms.class) {
                MockKms mockKms = new MockKms();
                mockKmses.add(mockKms);
                return mockKms;
            }
            if (parameter.getType() != Mpl.class) {
                return inputValues.get(inputValueIndex(parameterContext.getIndex()));
            }
            int mplIndex = mplIndex(parameterContext.getIndex());
            if (mplIndex >= mpls.size()) {
                throw new IllegalStateException("@KeyringTest " + testMethod.getName() + " takes "
                    + (mplIndex + 1) + " Mpl parameters, but each run has " + mpls.size()
                    + (settings.pairs() ? "" : "; set pairs = true for an encrypting and a decrypting Mpl"));
            }
            return mpls.get(mplIndex);
        }

        /** The class of a primitive's values, such as Integer for int, so an Integer input fits an int parameter. */
        private static Class<?> boxed(Class<?> type) {
            if (!type.isPrimitive()) {
                return type;
            }
            if (type == int.class) {
                return Integer.class;
            }
            if (type == long.class) {
                return Long.class;
            }
            if (type == boolean.class) {
                return Boolean.class;
            }
            return type;
        }

        @Override
        public void afterEach(ExtensionContext context) {
            for (MockKms mockKms : mockKmses) {
                mockKms.close();
            }
            mockKmses.clear();
            if (mpls != null) {
                for (Mpl mpl : mpls) {
                    mpl.throwUnresolvedFailure();
                }
            }
        }

        /** How many parameters that take an input value come before parameter {@code index}. */
        private int inputValueIndex(int index) {
            Parameter[] parameters = testMethod.getParameters();
            int count = 0;
            for (int i = 0; i < index; i++) {
                Class<?> type = parameters[i].getType();
                if (type != Mpl.class && type != MockKms.class) {
                    count++;
                }
            }
            return count;
        }

        /** How many {@code Mpl} parameters come before parameter {@code index}. */
        private int mplIndex(int index) {
            Parameter[] parameters = testMethod.getParameters();
            int count = 0;
            for (int i = 0; i < index; i++) {
                if (parameters[i].getType() == Mpl.class) {
                    count++;
                }
            }
            return count;
        }
    }
}
