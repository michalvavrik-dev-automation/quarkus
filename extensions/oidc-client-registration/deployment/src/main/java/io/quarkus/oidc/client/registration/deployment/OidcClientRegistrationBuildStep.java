package io.quarkus.oidc.client.registration.deployment;

import java.io.IOException;
import java.util.function.BooleanSupplier;

import jakarta.inject.Singleton;

import org.jboss.jandex.ClassType;

import io.quarkus.arc.deployment.SyntheticBeanBuildItem;
import io.quarkus.core.Phase;
import io.quarkus.core.deployment.service.ServiceRegistrar;
import io.quarkus.deployment.Feature;
import io.quarkus.deployment.annotations.BuildProducer;
import io.quarkus.deployment.annotations.BuildStep;
import io.quarkus.deployment.annotations.BuildSteps;
import io.quarkus.deployment.builditem.ExtensionSslNativeSupportBuildItem;
import io.quarkus.oidc.client.registration.OidcClientRegistration;
import io.quarkus.oidc.client.registration.OidcClientRegistrations;
import io.quarkus.oidc.client.registration.runtime.DefaultOidcClientRegistrationCreator;
import io.quarkus.oidc.client.registration.runtime.OidcClientRegistrationRecorder;
import io.quarkus.oidc.client.registration.runtime.OidcClientRegistrationsConfig;
import io.quarkus.proxy.ProxyConfigurationRegistry;
import io.quarkus.tls.TlsConfigurationRegistry;
import io.vertx.core.Vertx;

@BuildSteps(onlyIf = OidcClientRegistrationBuildStep.IsEnabled.class)
public class OidcClientRegistrationBuildStep {

    @BuildStep
    ExtensionSslNativeSupportBuildItem enableSslInNative() {
        return new ExtensionSslNativeSupportBuildItem(Feature.OIDC_CLIENT_REGISTRATION);
    }

    @BuildStep
    void setup(ServiceRegistrar serviceRegistrar, BuildProducer<SyntheticBeanBuildItem> syntheticBean) {
        serviceRegistrar
                .forService(OidcClientRegistrations.class)
                .atPhase(Phase.DATA)
                .require(ProxyConfigurationRegistry.class)
                .require(TlsConfigurationRegistry.class)
                .require(Vertx.class)
                .require(OidcClientRegistrationsConfig.class)
                .onStart((ctx, proxyConfigurationRegistry, tlsConfigurationRegistry, vertx, runtimeConfig) -> {
                    OidcClientRegistrations oidcClientRegistrations = OidcClientRegistrationRecorder.setup(vertx,
                            tlsConfigurationRegistry, proxyConfigurationRegistry, runtimeConfig);
                    ctx.onStop(() -> {
                        try {
                            oidcClientRegistrations.close();
                        } catch (IOException e) {
                            throw new RuntimeException(e);
                        }
                    });
                    return oidcClientRegistrations;
                });

        syntheticBean.produce(SyntheticBeanBuildItem.configure(OidcClientRegistrations.class).unremovable()
                .types(OidcClientRegistrations.class)
                .serviceValue(OidcClientRegistrations.class)
                .scope(Singleton.class)
                .setRuntimeInit()
                .done());

        // The default client registration is null when it is not configured. A serviceValue() bean cannot
        // have a null instance, therefore this bean reads it from the OidcClientRegistrations bean instead.
        syntheticBean.produce(SyntheticBeanBuildItem.configure(OidcClientRegistration.class).unremovable()
                .types(OidcClientRegistration.class)
                .creator(DefaultOidcClientRegistrationCreator.class)
                .addInjectionPoint(ClassType.create(OidcClientRegistrations.class))
                .scope(Singleton.class)
                .setRuntimeInit()
                .done());
    }

    public static class IsEnabled implements BooleanSupplier {
        OidcClientRegistrationBuildTimeConfig config;

        public boolean getAsBoolean() {
            return config.enabled();
        }
    }
}
