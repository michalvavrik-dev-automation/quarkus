package io.quarkus.oidc.client.registration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.fail;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import io.quarkus.test.QuarkusExtensionTest;

public class OidcClientRegistrationMissingUrlTest {

    @RegisterExtension
    static final QuarkusExtensionTest test = new QuarkusExtensionTest()
            .withEmptyApplication()
            // without the Keycloak Dev Service, the 'quarkus.oidc-client-registration.auth-server-url' is not set
            .overrideConfigKey("quarkus.devservices.enabled", "false")
            .overrideRuntimeConfigKey("quarkus.oidc-client-registration.metadata.client-name", "Default Test Client")
            .assertException(t -> assertThat(t)
                    .isInstanceOf(RuntimeException.class)
                    .hasMessage("'Default' client registration configuration is not initialized"));

    @Test
    public void testApplicationFailsToStart() {
        fail("The application must not start when the client registration endpoint URL is not configured");
    }
}
