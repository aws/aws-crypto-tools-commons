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
import java.util.stream.Stream;
import org.junit.jupiter.api.extension.AfterEachCallback;
import org.junit.jupiter.api.extension.BeforeEachCallback;
import org.junit.jupiter.api.extension.Extension;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.api.extension.ParameterContext;
import org.junit.jupiter.api.extension.ParameterResolver;
import org.junit.jupiter.api.extension.TestTemplateInvocationContext;
import org.junit.jupiter.api.extension.TestTemplateInvocationContextProvider;
import org.junit.platform.commons.support.AnnotationSupport;
import org.junit.platform.commons.support.ReflectionSupport;

/**
 * Runs a {@link KeyringTest} once for each language server, or once for each input and language server.
 *
 * <p>JUnit asks this provider for the runs of a test when it plans the test class.
 * Each run is one {@link Run}, which JUnit also uses as an extension for that run alone:
 * <ol>
 *   <li>Before the test body, {@link Run#beforeEach} calls {@link FeatureGate#require}.
 *       That call skips the run when a language does not support the feature,
 *       and it records the decision in feature-gate-log.jsonl.
 *       Then it builds the test server client.
 *       In a dry run, building the client stops the run and logs it as one that would run.</li>
 *   <li>{@link Run#resolveParameter} gives the test its {@link Mpl} and its input.
 *       It also gives a new {@link FakeKms} for each {@code FakeKms} parameter.</li>
 *   <li>After the test body, {@link Run#afterEach} stops each FakeKms.</li>
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
        Set<String> features = Set.copyOf(Arrays.asList(settings.feature()));
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
        private final Object input;
        /** A {@link LanguageServerTarget}, or a {@link TargetPair} for a test with {@link KeyringTest#pairs()}. */
        private final Object languageServer;
        /** One per {@code Mpl} parameter, in parameter order. Set by {@link #beforeEach}. */
        private List<Mpl> mpls;
        /** One per {@code FakeKms} parameter. {@link #afterEach} stops them. */
        private final List<FakeKms> fakeKmses = new ArrayList<>();

        Run(Set<String> features, KeyringTest settings, Method testMethod, Object input, Object languageServer) {
            this.features = features;
            this.settings = settings;
            this.testMethod = testMethod;
            this.input = input;
            this.languageServer = languageServer;
        }

        /** Fill the {@link KeyringTest#name()} pattern the same way a {@code @ParameterizedTest} name is. */
        @Override
        public String getDisplayName(int invocationIndex) {
            List<Object> arguments = input == NO_INPUT ? List.of(languageServer) : List.of(input, languageServer);
            String pattern = settings.name();
            if (pattern.isEmpty()) {
                pattern = "[" + String.join(", ", settings.feature()) + "] " + testMethod.getName()
                    + (input == NO_INPUT ? " {0}" : " {0} {1}");
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

        /** An {@code Mpl}, a {@code FakeKms}, or a parameter that the input fits. */
        @Override
        public boolean supportsParameter(ParameterContext parameterContext, ExtensionContext extensionContext) {
            Class<?> type = parameterContext.getParameter().getType();
            return type == Mpl.class || type == FakeKms.class
                || (input != NO_INPUT && boxed(type).isInstance(input));
        }

        @Override
        public Object resolveParameter(ParameterContext parameterContext, ExtensionContext extensionContext) {
            Parameter parameter = parameterContext.getParameter();
            if (parameter.getType() == FakeKms.class) {
                FakeKms fakeKms = new FakeKms();
                fakeKmses.add(fakeKms);
                return fakeKms;
            }
            if (parameter.getType() != Mpl.class) {
                return input;
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
            for (FakeKms fakeKms : fakeKmses) {
                fakeKms.close();
            }
            fakeKmses.clear();
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
