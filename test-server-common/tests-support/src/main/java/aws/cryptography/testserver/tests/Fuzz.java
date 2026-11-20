package aws.cryptography.testserver.tests;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.lang.reflect.Array;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Random;
import java.util.function.Function;

/**
 * Adds random examples to the shared input lists, such as {@link KmsInputs}, when fuzzing is turned on.
 *
 * <p>A normal run tests only each list's fixed examples.
 * To add random examples, set {@code TESTSERVER_FUZZ} (or {@code -Dtestserver.fuzz}) to how many to add to each list:
 *
 * <pre>{@code
 * TESTSERVER_FUZZ=200 make test-server
 * }</pre>
 *
 * <p>Each random example's name has its number and the seed that made it, such as
 * {@code fuzz 12 seed=42: empty ARN part 3}.
 * Set {@code TESTSERVER_FUZZ_SEED} (or {@code -Dtestserver.fuzzSeed}) to that seed to make the same examples again.
 *
 * @param count how many random examples to add to each list
 * @param seed the seed that every list's random examples come from
 * @param log a file that gets one JSON line per random example, or null for no log
 */
public record Fuzz(int count, long seed, Path log) {

    public static final String COUNT_PROPERTY = "testserver.fuzz";
    public static final String COUNT_ENV = "TESTSERVER_FUZZ";
    public static final String SEED_PROPERTY = "testserver.fuzzSeed";
    public static final String SEED_ENV = "TESTSERVER_FUZZ_SEED";
    /** The build file sets this to a file next to the JUnit XML, so the report artifact holds the log. */
    public static final String LOG_PROPERTY = "testserver.fuzzLog";

    /** No random examples. */
    public static final Fuzz NONE = new Fuzz(0, 0, null);

    private static final ObjectMapper JSON = new ObjectMapper();
    private static final int LOGGED_VALUE_LENGTH = 200;

    private static Fuzz configured;

    /**
     * The settings for this run, read once.
     * Every list then uses the same seed, so the one seed in a report makes every list again.
     */
    public static synchronized Fuzz configured() {
        if (configured == null) {
            String count = setting(COUNT_PROPERTY, COUNT_ENV);
            String seed = setting(SEED_PROPERTY, SEED_ENV);
            String log = System.getProperty(LOG_PROPERTY);
            Path logFile = log == null || log.isBlank() ? null : Path.of(log);
            // The log file outlives the test run, and a log from an earlier run would name values this run never made.
            if (logFile != null) {
                try {
                    Files.deleteIfExists(logFile);
                } catch (IOException e) {
                    throw new UncheckedIOException("could not remove the old fuzz log " + logFile, e);
                }
            }
            configured = count == null ? NONE : new Fuzz(Integer.parseInt(count),
                seed == null ? new Random().nextLong() : Long.parseLong(seed), logFile);
        }
        return configured;
    }

    /**
     * {@code count} examples from {@code make}, each with its number and the seed in its name.
     * Each one is also written to the log, under {@code list}.
     *
     * @param list the name of the list the examples join, such as {@code invalidKmsIdentifiers}
     */
    public <T> List<Example<T>> examples(String list, Function<Random, Example<T>> make) {
        // Each list gets its own random sequence, so two lists with the same seed do not make matching choices.
        Random random = new Random(seed ^ list.hashCode());
        List<Example<T>> examples = new ArrayList<>();
        for (int i = 0; i < count; i++) {
            Example<T> made = make.apply(random);
            Example<T> example = new Example<>("fuzz " + i + " seed=" + seed + ": " + made.name(), made.value());
            examples.add(example);
            writeToLog(list, i, made.name(), example);
        }
        return examples;
    }

    // The dashboard reads this log to show each random value and which tests used it.
    // A test class can ask for the same list more than once, so the log can repeat a line.
    private void writeToLog(String list, int index, String what, Example<?> example) {
        if (log == null) {
            return;
        }
        String value = example.value() instanceof byte[] bytes
            ? HexFormat.of().formatHex(bytes)
            : String.valueOf(example.value());
        Map<String, Object> entry = new LinkedHashMap<>();
        entry.put("family", callerOutside(Fuzz.class).map(Class::getSimpleName).orElse(null));
        entry.put("list", list);
        entry.put("test", testClass().map(Class::getName).orElse(null));
        entry.put("seed", seed);
        entry.put("index", index);
        entry.put("what", what);
        entry.put("name", example.name());
        entry.put("length", lengthOf(example.value()));
        entry.put("value", shorten(value));
        String line;
        try {
            line = JSON.writeValueAsString(entry) + "\n";
        } catch (JsonProcessingException e) {
            throw new UncheckedIOException(e);
        }
        synchronized (Fuzz.class) {
            try {
                Files.createDirectories(log.toAbsolutePath().getParent());
                Files.writeString(log, line, StandardOpenOption.CREATE, StandardOpenOption.APPEND);
            } catch (IOException e) {
                throw new UncheckedIOException("could not write the fuzz log " + log, e);
            }
        }
    }

    /** The class that called {@code skipped}, such as the input class that called {@link #examples}. */
    private static Optional<Class<?>> callerOutside(Class<?> skipped) {
        return StackWalker.getInstance(StackWalker.Option.RETAIN_CLASS_REFERENCE)
            .walk(frames -> frames.map(StackWalker.StackFrame::getDeclaringClass)
                .filter(c -> c != skipped)
                .findFirst());
    }

    /** The test class that asked for the list, found by the Test or Tests at the end of its name. */
    private static Optional<Class<?>> testClass() {
        return StackWalker.getInstance(StackWalker.Option.RETAIN_CLASS_REFERENCE)
            .walk(frames -> frames.map(StackWalker.StackFrame::getDeclaringClass)
                .filter(c -> c.getSimpleName().endsWith("Test") || c.getSimpleName().endsWith("Tests"))
                .findFirst());
    }

    /** Characters in a string, entries in a list or map, bytes in an array; null for anything else. */
    private static Integer lengthOf(Object value) {
        if (value instanceof CharSequence text) {
            return text.length();
        }
        if (value instanceof Collection<?> collection) {
            return collection.size();
        }
        if (value instanceof Map<?, ?> map) {
            return map.size();
        }
        if (value != null && value.getClass().isArray()) {
            return Array.getLength(value);
        }
        return null;
    }

    // An 8192-character grant token would make the log huge, so long values keep their start and end.
    private static String shorten(String value) {
        if (value.length() <= LOGGED_VALUE_LENGTH) {
            return value;
        }
        // Cut between code points, because half of an emoji cannot be written as UTF-8.
        int half = LOGGED_VALUE_LENGTH / 2;
        int startEnd = value.offsetByCodePoints(0, value.codePointCount(0, half));
        int endStart = value.offsetByCodePoints(value.length(),
            -value.codePointCount(value.length() - half, value.length()));
        return value.substring(0, startEnd) + "..." + value.substring(endStart);
    }

    private static String setting(String property, String env) {
        String value = System.getProperty(property);
        if (value == null || value.isBlank()) {
            value = System.getenv(env);
        }
        return value == null || value.isBlank() ? null : value.trim();
    }
}
