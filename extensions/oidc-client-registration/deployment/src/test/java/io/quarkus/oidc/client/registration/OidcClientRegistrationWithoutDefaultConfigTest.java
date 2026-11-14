package io.quarkus.oidc.client.registration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;

import jakarta.inject.Inject;
import jakarta.inject.Singleton;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import io.quarkus.test.QuarkusExtensionTest;

public class OidcClientRegistrationWithoutDefaultConfigTest {

    @RegisterExtension
    static final QuarkusExtensionTest test = new QuarkusExtensionTest()
            .withApplicationRoot((jar) -> jar.addClasses(TestClientRegistrations.class))
            // the only configured client registration is disabled, therefore no OIDC provider is required
            .overrideConfigKey("quarkus.devservices.enabled", "false")
            .overrideRuntimeConfigKey("quarkus.oidc-client-registration.named.registration-enabled", "false");

    @Inject
    TestClientRegistrations testClientRegistrations;

    @Test
    public void testDefaultClientRegistrationIsNull() {
        assertThat(testClientRegistrations.clientRegistrations.getClientRegistration()).isNull();
        assertThat(testClientRegistrations.clientRegistration).isNull();
    }

    @Test
    public void testNamedClientRegistrationIsAvailable() {
        assertThat(testClientRegistrations.clientRegistrations.getClientRegistration("named")).isNotNull();
    }

    @Test
    public void testClientRegistrationsCanBeClosed() {
        assertThatCode(testClientRegistrations.clientRegistrations::close).doesNotThrowAnyException();
    }

    @Singleton
    public static final class TestClientRegistrations {

        @Inject
        OidcClientRegistration clientRegistration;

        @Inject
        OidcClientRegistrations clientRegistrations;
    }
}
