package io.quarkus.oidc.client.registration;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import io.quarkus.test.QuarkusExtensionTest;

public class ProbeStartupFailureTest {

    @RegisterExtension
    static final QuarkusExtensionTest test = new QuarkusExtensionTest()
            .withEmptyApplication()
            .overrideConfigKey("quarkus.devservices.enabled", "false")
            .overrideRuntimeConfigKey("quarkus.oidc-client-registration.named.metadata.client-name", "Named Client")
            .assertException(t -> {
                System.out.println("PROBE2 startup failure: " + t);
                Throwable c = t.getCause();
                while (c != null) {
                    System.out.println("PROBE2   caused by: " + c);
                    c = c.getCause();
                }
                for (Throwable s : t.getSuppressed()) {
                    System.out.println("PROBE2   suppressed: " + s);
                }
            });

    @Test
    public void probe() {
        System.out.println("PROBE2 application started without failure");
    }
}
