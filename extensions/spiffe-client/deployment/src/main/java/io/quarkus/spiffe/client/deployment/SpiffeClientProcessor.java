package io.quarkus.spiffe.client.deployment;

import static io.quarkus.arc.processor.DotNames.APPLICATION_SCOPED;

import java.util.Collection;
import java.util.List;
import java.util.function.BooleanSupplier;

import org.jboss.jandex.AnnotationInstance;
import org.jboss.jandex.IndexView;

import io.quarkus.arc.deployment.AdditionalBeanBuildItem;
import io.quarkus.arc.runtime.BeanContainer;
import io.quarkus.core.Phase;
import io.quarkus.core.deployment.service.ServiceRegistrar;
import io.quarkus.deployment.Capabilities;
import io.quarkus.deployment.Capability;
import io.quarkus.deployment.annotations.BuildStep;
import io.quarkus.deployment.builditem.CombinedIndexBuildItem;
import io.quarkus.deployment.builditem.FeatureBuildItem;
import io.quarkus.spiffe.client.runtime.internal.SpiffeTlsConfigurationManager;
import io.quarkus.spiffe.client.runtime.internal.SpiffeTlsConfigurationSupplier;
import io.quarkus.spiffe.svid.x509.X509Svid;
import io.quarkus.spiffe.svid.x509.X509SvidClient;
import io.quarkus.tls.TlsConfigurationRegistry;
import io.quarkus.tls.deployment.spi.TlsCertificateBuildItem;

final class SpiffeClientProcessor {

    private static final String CLIENT_IMPL_CLASS = "io.quarkus.spiffe.client.runtime.internal.SpiffeClientImpl";
    static final String FEATURE = "spiffe-client";

    @BuildStep
    FeatureBuildItem feature() {
        return new FeatureBuildItem(FEATURE);
    }

    @BuildStep(onlyIf = SpiffeClientEnabled.class)
    AdditionalBeanBuildItem registerClientAsCdiBean() {
        return AdditionalBeanBuildItem.builder()
                .addBeanClass(CLIENT_IMPL_CLASS)
                .setDefaultScope(APPLICATION_SCOPED)
                .setUnremovable()
                .build();
    }

    @BuildStep(onlyIf = SpiffeClientEnabled.class)
    List<TlsCertificateBuildItem> registerTlsConfigurations(CombinedIndexBuildItem combinedIndexBuildItem,
            ServiceRegistrar serviceRegistrar, Capabilities capabilities) {
        final IndexView index = combinedIndexBuildItem.getIndex();
        final Collection<AnnotationInstance> x509SvidInstances = index.getAnnotationsWithRepeatable(X509Svid.class, index);

        if (x509SvidInstances.isEmpty()) {
            return List.of();
        } else {
            if (capabilities.isMissing(Capability.TLS_REGISTRY)) {
                throw new RuntimeException(X509Svid.class.getName() + " annotation cannot be used without TLS registry");
            }
            serviceRegistrar
                    .forService(SpiffeTlsConfigurationManager.class)
                    .atPhase(Phase.STATIC_INIT)
                    .require(BeanContainer.class)
                    .onStart((ctx, container) -> SpiffeTlsConfigurationManager.createFrom(ctx::onStop,
                            container.beanInstance(X509SvidClient.class)));
            serviceRegistrar
                    .forService("io.quarkus.spiffe.client.initialize-tls-configurations")
                    .atPhase(Phase.DATA)
                    .require(SpiffeTlsConfigurationManager.class)
                    .after(TlsConfigurationRegistry.class)
                    .before("io.quarkus.arc.startup-event")
                    .onStartAsync((ctx, provider) -> provider.initialize(ctx::startComplete, ctx::startFailed));

            return x509SvidInstances.stream()
                    .map(annotationInstance -> {
                        // FIXME: validate not created this tls config already and that the same spiffe id not used yet
                        String tlsConfigurationName = annotationInstance.value("tls").asString();
                        // TODO: validate spiffe id unique
                        String spiffeId = annotationInstance.valueWithDefault(index, "spiffeId").asString();
                        return new SpiffeTlsConfigurationSupplier(tlsConfigurationName, spiffeId);
                    })
                    .map(s -> new TlsCertificateBuildItem(s.tlsConfigurationName(), s))
                    .toList();
        }
    }

    static final class SpiffeClientEnabled implements BooleanSupplier {

        private final boolean enabled;

        SpiffeClientEnabled(SpiffeClientBuildTimeConfig config) {
            this.enabled = config.enabled();
        }

        @Override
        public boolean getAsBoolean() {
            return enabled;
        }
    }
}
