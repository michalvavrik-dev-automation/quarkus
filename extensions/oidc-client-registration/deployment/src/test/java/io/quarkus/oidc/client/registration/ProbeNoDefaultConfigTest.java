package io.quarkus.oidc.client.registration;

import jakarta.enterprise.inject.Instance;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import io.quarkus.test.QuarkusExtensionTest;

public class ProbeNoDefaultConfigTest {

    @RegisterExtension
    static final QuarkusExtensionTest test = new QuarkusExtensionTest()
            .withApplicationRoot((jar) -> jar.addClasses(Holder.class))
            .overrideConfigKey("quarkus.devservices.enabled", "false")
            .overrideRuntimeConfigKey("quarkus.oidc-client-registration.named.registration-enabled", "false");

    @Inject
    OidcClientRegistrations registrations;

    @Inject
    Instance<OidcClientRegistration> defaultRegistration;

    @Inject
    Instance<Holder> holder;

    @Test
    public void probe() {
        System.out.println("PROBE default via registrations: " + registrations.getClientRegistration());
        System.out.println("PROBE named: " + registrations.getClientRegistration("named"));
        System.out.println("PROBE map keys: " + registrations.getClientRegistrations().keySet());
        try {
            System.out.println("PROBE default bean: " + defaultRegistration.get());
        } catch (Throwable t) {
            print("PROBE default bean threw: ", t);
        }
        try {
            Holder h = holder.get();
            System.out.println("PROBE holder created, clientReg=" + h.clientReg + ", clientRegs=" + h.clientRegs);
        } catch (Throwable t) {
            print("PROBE holder creation threw: ", t);
        }
    }

    private static void print(String prefix, Throwable t) {
        System.out.println(prefix + t);
        Throwable c = t.getCause();
        while (c != null) {
            System.out.println("PROBE   caused by: " + c);
            c = c.getCause();
        }
    }

    @Singleton
    public static class Holder {
        @Inject
        OidcClientRegistration clientReg;

        @Inject
        OidcClientRegistrations clientRegs;
    }
}
