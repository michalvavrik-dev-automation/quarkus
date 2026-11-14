package io.quarkus.oidc.client.registration.runtime;

import io.quarkus.arc.BeanCreator;
import io.quarkus.arc.SyntheticCreationalContext;
import io.quarkus.oidc.client.registration.OidcClientRegistration;
import io.quarkus.oidc.client.registration.OidcClientRegistrations;

public final class DefaultOidcClientRegistrationCreator implements BeanCreator<OidcClientRegistration> {

    @Override
    public OidcClientRegistration create(SyntheticCreationalContext<OidcClientRegistration> context) {
        // null if the default OIDC client registration configuration is not available
        return context.getInjectedReference(OidcClientRegistrations.class).getClientRegistration();
    }
}
