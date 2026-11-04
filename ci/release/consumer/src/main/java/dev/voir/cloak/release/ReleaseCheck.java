package dev.voir.cloak.release;

import dev.voir.cloak.api.models.Meta;
import dev.voir.cloak.server.CloakServer;
import dev.voir.cloak.spring.auth.CloakPrincipalResolver;
import java.lang.reflect.Proxy;
import java.util.UUID;
import javax.sql.DataSource;

/**
 * Runs the staged artifacts the way a Java host would, without a database: it builds the server,
 * reads its capabilities, implements the principal resolver, loads the auto-configuration and the
 * wire models, and checks that an invalid host user id is refused before any query.
 */
public final class ReleaseCheck {
    private ReleaseCheck() {}

    /**
     * Fails with a message unless the staged release works.
     *
     * @param args The release version.
     */
    public static void main(String[] args) throws Exception {
        String version = args[0];

        // A data source that is never asked for a connection: nothing here reaches a database.
        DataSource unused = (DataSource) Proxy.newProxyInstance(
                ReleaseCheck.class.getClassLoader(),
                new Class<?>[] {DataSource.class},
                (proxy, method, arguments) -> {
                    throw new IllegalStateException("The release check must not touch a database: " + method.getName());
                });
        CloakServer cloak = new CloakServer(unused);
        check(cloak.meta().getProtocolVersion() == 1, "protocol version 1");
        check(cloak.meta().getLimits().getMaxBatchSize() == 100, "batch size 100");

        CloakPrincipalResolver resolver = request -> "release-check";
        check(resolver.resolve(null).equals("release-check"), "a Java resolver");
        try {
            cloak.getAccess().role("", UUID.randomUUID());
            throw new IllegalStateException("An empty host user id was accepted.");
        } catch (IllegalArgumentException expected) {
            // Refused before any query.
        }

        Class.forName("dev.voir.cloak.spring.CloakAutoConfiguration");
        Class.forName(Meta.class.getName());
        System.out.println("Cloak " + version + " resolves from the staged repository and runs.");
    }

    /** Fails unless [condition] holds. */
    private static void check(boolean condition, String what) {
        if (!condition) throw new IllegalStateException("Release check failed: " + what);
    }
}
