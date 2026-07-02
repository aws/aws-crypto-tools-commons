package aws.cryptography.esdk.testserver.orchestrator.launch;

import aws.cryptography.esdk.testserver.orchestrator.config.ConfigurationEntry;
import aws.cryptography.esdk.testserver.orchestrator.source.ResolvedSource;
import aws.cryptography.esdk.testserver.server.handler.EsdkTestServerHandlers;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.URI;
import software.amazon.smithy.java.server.Server;

/**
 * Launches the Java {@code Language_Server} in-process on its configured port
 * (Requirement 9.4), reusing the same {@link EsdkTestServerHandlers#service()}
 * assembly point the checkpoint uses, so the orchestrated run exercises exactly
 * the shipped server wiring: smithy-java-generated request decoding / response &amp;
 * error encoding over one shared, thread-safe {@code Client_Registry}, delegating
 * to the real AWS Encryption SDK for Java.
 *
 * <p>Only {@code "java"} is wired end-to-end for this pass; any other language
 * aborts with {@link ServerLaunchException.Category#UNSUPPORTED_LANGUAGE} because
 * no other language server exists yet (tasks 9-10 add them).
 *
 * <p><b>Known limitation (task 11).</b> Every {@link ResolvedSource} variant for
 * Java currently launches the same in-process server backed by the published ESDK
 * artifact on the classpath; wiring the live working tree / a submodule commit /
 * a specific artifact version into the Java build is task 11. The
 * source-resolution logic itself is fully implemented and unit-tested here so the
 * generic code paths exist.
 */
public final class JavaServerLauncher implements Launcher {

    @Override
    public LaunchedServer launch(ConfigurationEntry entry, ResolvedSource source)
            throws ServerLaunchException {
        String language = entry.language();
        if (!"java".equals(language)) {
            throw new ServerLaunchException(language,
                ServerLaunchException.Category.UNSUPPORTED_LANGUAGE,
                "no Language_Server implementation is available for language '" + language
                    + "' yet (parked; tasks 9-10)");
        }

        int port = entry.port();

        // Surface a port conflict as an abort that names the language (Req 9.6).
        // Probing with a short-lived bind is deterministic for the pre-bind
        // conflict integration test; the server binds immediately afterwards.
        if (!isPortAvailable(port)) {
            throw new ServerLaunchException(language,
                ServerLaunchException.Category.PORT_CONFLICT,
                "port " + port + " is already in use; cannot bind the "
                    + language + " Language_Server");
        }

        // Build + launch. Any failure to assemble/bind the server is a build
        // failure that names the language (Requirements 11.4, 12.8).
        try {
            EsdkTestServerHandlers handlers = new EsdkTestServerHandlers();
            Server server = Server.builder()
                .endpoints(port)
                .addService(handlers.service())
                .build();
            server.start();
            URI endpoint = URI.create("http://127.0.0.1:" + port);
            return new LaunchedServer(language, port, endpoint, () -> server.shutdown().join());
        } catch (RuntimeException e) {
            throw new ServerLaunchException(language,
                ServerLaunchException.Category.BUILD_FAILURE,
                "failed to build/launch the " + language + " Language_Server: " + e.getMessage(), e);
        }
    }

    /** @return true if a TCP server socket can be bound to {@code port} on loopback. */
    private static boolean isPortAvailable(int port) {
        try (ServerSocket probe = new ServerSocket()) {
            probe.setReuseAddress(false);
            probe.bind(new InetSocketAddress("127.0.0.1", port));
            return true;
        } catch (IOException e) {
            return false;
        }
    }
}
