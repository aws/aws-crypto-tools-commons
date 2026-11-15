package aws.cryptography.testserver.mutation;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.io.OutputStream;
import java.lang.instrument.ClassFileTransformer;
import java.lang.instrument.Instrumentation;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.ProtectionDomain;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * A Java agent that turns one mutant of the library on or off in a running JVM.
 *
 * <p>Usage: {@code -javaagent:jvm-mutants.jar=port=<port>,dir=<dir>}
 *
 * <p>At start it writes the JVM's class path to {@code <dir>/classpath.txt}, so
 * {@link ListMutants} reads the same class files this JVM loads. It then listens
 * on {@code 127.0.0.1:<port>} for {@code POST /control/mutant} with a mutant id
 * as the body. Id 0 turns every mutant off. Any other id loads
 * {@code <dir>/bytes/<id>/<class name>.class}, which ListMutants wrote, and
 * swaps that class for it with {@link Instrumentation#retransformClasses}. The
 * class that the last mutant changed goes back to its original bytes at the
 * same time. A class that is not loaded yet gets the mutant when it loads.
 *
 * <p>The reply is 200 when the swap worked, and 409 with the reason when the
 * JVM refused it. The mutation driver then counts the mutant as unviable.
 */
public final class MutantSwitch implements ClassFileTransformer {

    private final Instrumentation instrumentation;
    private final Path bytes;
    private String activeClass;
    private byte[] activeBytes;

    private MutantSwitch(Instrumentation instrumentation, Path bytes) {
        this.instrumentation = instrumentation;
        this.bytes = bytes;
    }

    public static void premain(String arguments, Instrumentation instrumentation) throws IOException {
        Map<String, String> options = new HashMap<>();
        for (String option : arguments.split(",")) {
            String[] pair = option.split("=", 2);
            options.put(pair[0], pair[1]);
        }
        Path dir = Path.of(options.get("dir"));
        Files.createDirectories(dir);
        Files.writeString(dir.resolve("classpath.txt"), System.getProperty("java.class.path"));

        MutantSwitch mutantSwitch = new MutantSwitch(instrumentation, dir.resolve("bytes"));
        instrumentation.addTransformer(mutantSwitch, true);
        HttpServer server = HttpServer.create(
            new InetSocketAddress(InetAddress.getLoopbackAddress(), Integer.parseInt(options.get("port"))), 0);
        server.createContext("/control/mutant", mutantSwitch::handle);
        server.start();
    }

    private void handle(HttpExchange exchange) throws IOException {
        int status;
        String reply;
        try {
            String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8).trim();
            turnOn(Integer.parseInt(body));
            status = 200;
            reply = "ok";
        } catch (Exception | LinkageError e) {
            status = 409;
            reply = e.toString();
        }
        byte[] out = reply.getBytes(StandardCharsets.UTF_8);
        exchange.sendResponseHeaders(status, out.length);
        try (OutputStream stream = exchange.getResponseBody()) {
            stream.write(out);
        }
    }

    private synchronized void turnOn(int id) throws Exception {
        String previous = activeClass;
        String next = null;
        byte[] nextBytes = null;
        if (id != 0) {
            try (DirectoryStream<Path> files = Files.newDirectoryStream(bytes.resolve(String.valueOf(id)), "*.class")) {
                for (Path file : files) {
                    next = file.getFileName().toString().replaceFirst("\\.class$", "");
                    nextBytes = Files.readAllBytes(file);
                }
            }
            if (next == null) {
                throw new IOException("no class file for mutant " + id);
            }
        }
        activeClass = next;
        activeBytes = nextBytes;
        List<Class<?>> changed = new ArrayList<>();
        for (Class<?> loaded : instrumentation.getAllLoadedClasses()) {
            String name = loaded.getName();
            if ((name.equals(previous) || name.equals(next)) && instrumentation.isModifiableClass(loaded)) {
                changed.add(loaded);
            }
        }
        try {
            if (!changed.isEmpty()) {
                instrumentation.retransformClasses(changed.toArray(new Class<?>[0]));
            }
        } catch (Exception | LinkageError e) {
            // Leave the library unmutated, so the next mutant starts from the original classes.
            activeClass = null;
            activeBytes = null;
            if (!changed.isEmpty()) {
                instrumentation.retransformClasses(changed.toArray(new Class<?>[0]));
            }
            throw e;
        }
    }

    @Override
    public synchronized byte[] transform(ClassLoader loader, String className, Class<?> redefining,
            ProtectionDomain domain, byte[] original) {
        // Returning null keeps the original bytes, which is how a retransform turns a mutant off.
        if (activeClass != null && className != null && className.replace('/', '.').equals(activeClass)) {
            return activeBytes;
        }
        return null;
    }
}
