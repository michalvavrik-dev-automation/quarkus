package io.quarkus.keycloak.admin.resteasy.client.deployment;

import java.util.ArrayList;
import java.util.List;

import jakarta.enterprise.context.RequestScoped;

import org.jboss.jandex.ClassInfo;
import org.jboss.jandex.DotName;
import org.jboss.jandex.Type;
import org.jboss.resteasy.client.jaxrs.internal.ResteasyClientBuilderImpl;
import org.jboss.resteasy.client.jaxrs.internal.proxy.ProxyBuilderImpl;
import org.jboss.resteasy.client.jaxrs.internal.proxy.ResteasyClientProxy;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.jackson3.JacksonProvider3;
import org.keycloak.admin.client.spi.ResteasyClientProvider;
import org.keycloak.common.util.MultivaluedHashMap;

import io.quarkus.arc.deployment.SyntheticBeanBuildItem;
import io.quarkus.core.Phase;
import io.quarkus.core.deployment.service.ServiceRegistrar;
import io.quarkus.deployment.Feature;
import io.quarkus.deployment.annotations.BuildProducer;
import io.quarkus.deployment.annotations.BuildStep;
import io.quarkus.deployment.annotations.Produce;
import io.quarkus.deployment.builditem.AdditionalApplicationArchiveMarkerBuildItem;
import io.quarkus.deployment.builditem.CombinedIndexBuildItem;
import io.quarkus.deployment.builditem.FeatureBuildItem;
import io.quarkus.deployment.builditem.ServiceStartBuildItem;
import io.quarkus.deployment.builditem.nativeimage.NativeImageProxyDefinitionBuildItem;
import io.quarkus.deployment.builditem.nativeimage.ReflectiveClassBuildItem;
import io.quarkus.deployment.builditem.nativeimage.ReflectiveHierarchyIgnoreWarningBuildItem;
import io.quarkus.deployment.builditem.nativeimage.ServiceProviderBuildItem;
import io.quarkus.keycloak.admin.client.common.deployment.KeycloakAdminClientInjectionEnabled;
import io.quarkus.keycloak.admin.client.common.runtime.KeycloakAdminClientConfig;
import io.quarkus.keycloak.admin.client.common.runtime.KeycloakAdminClientConfigUtil;
import io.quarkus.keycloak.admin.client.common.runtime.KeycloakAdminClientJsonMapper;
import io.quarkus.keycloak.admin.resteasy.client.runtime.KeycloakAdminClientCreator;
import io.quarkus.keycloak.admin.resteasy.client.runtime.KeycloakAdminResteasyClientProvider;
import io.quarkus.keycloak.admin.resteasy.client.runtime.KeycloakAdminResteasyClientRecorder;
import io.quarkus.tls.TlsConfigurationRegistry;

public class KeycloakAdminResteasyClientProcessor {

    private static final String ADMIN_CLIENT_RESOURCE_PACKAGE = "org.keycloak.admin.client.resource";
    private static final DotName PATH = DotName.createSimple("jakarta.ws.rs.Path");

    // Must be executed even if the extension is disabled, see https://github.com/quarkusio/quarkus/pull/26966/
    @BuildStep
    FeatureBuildItem featureBuildItem() {
        return new FeatureBuildItem(Feature.KEYCLOAK_ADMIN_RESTEASY_CLIENT);
    }

    @BuildStep
    ReflectiveHierarchyIgnoreWarningBuildItem marker(BuildProducer<AdditionalApplicationArchiveMarkerBuildItem> prod) {
        prod.produce(new AdditionalApplicationArchiveMarkerBuildItem("org/keycloak/admin/client/"));
        prod.produce(new AdditionalApplicationArchiveMarkerBuildItem("org/keycloak/representations"));
        return new ReflectiveHierarchyIgnoreWarningBuildItem(new ReflectiveHierarchyIgnoreWarningBuildItem.DotNameExclusion(
                DotName.createSimple(MultivaluedHashMap.class.getName())));
    }

    @BuildStep
    void reflect(BuildProducer<ReflectiveClassBuildItem> reflectiveClasses) {
        reflectiveClasses.produce(ReflectiveClassBuildItem.builder(ResteasyClientBuilderImpl.class, ProxyBuilderImpl.class)
                .reason(getClass().getName())
                .methods().build());
        // the Jackson provider of the Keycloak admin client is registered with the RESTEasy client at runtime,
        // when RESTEasy introspects it and injects the @Context fields declared along its class hierarchy
        // (the JSON providers of the Quarkus RESTEasy extensions get that treatment at build time)
        List<String> providerHierarchy = new ArrayList<>();
        for (Class<?> clazz = JacksonProvider3.class; clazz != Object.class; clazz = clazz.getSuperclass()) {
            providerHierarchy.add(clazz.getName());
        }
        reflectiveClasses.produce(ReflectiveClassBuildItem.builder(providerHierarchy.toArray(new String[0]))
                .reason(getClass().getName())
                .methods().fields().build());
    }

    /**
     * The admin client proxies its resource interfaces with RESTEasy. The RESTEasy client extension registers the
     * interfaces annotated with {@code @Path} for native, this registers the sub-resource interfaces without that
     * annotation, like {@code ClientPoliciesProfilesResource}.
     */
    @BuildStep
    void resourceProxies(CombinedIndexBuildItem index, BuildProducer<NativeImageProxyDefinitionBuildItem> proxies,
            BuildProducer<ReflectiveClassBuildItem> reflectiveClasses) {
        for (ClassInfo clazz : index.getIndex().getClassesInPackage(ADMIN_CLIENT_RESOURCE_PACKAGE)) {
            if (clazz.isInterface() && !clazz.hasDeclaredAnnotation(PATH)) {
                String name = clazz.name().toString();
                proxies.produce(new NativeImageProxyDefinitionBuildItem(name, ResteasyClientProxy.class.getName()));
                reflectiveClasses
                        .produce(ReflectiveClassBuildItem.builder(name).reason(getClass().getName()).methods().build());
            }
        }
    }

    @BuildStep
    ServiceProviderBuildItem clientProvider() {
        // the provider is loaded through the ServiceLoader when the Keycloak class is initialized
        return new ServiceProviderBuildItem(ResteasyClientProvider.class.getName(),
                KeycloakAdminResteasyClientProvider.class.getName());
    }

    @Produce(ServiceStartBuildItem.class)
    @BuildStep
    public void integrate(ServiceRegistrar serviceRegistrar) {
        serviceRegistrar
                .forService("io.quarkus.keycloak-admin-resteasy-client.client-provider")
                .atPhase(Phase.INIT)
                .require(TlsConfigurationRegistry.class)
                .require(KeycloakAdminClientConfig.class)
                .require(KeycloakAdminClientJsonMapper.class)
                .onStart((ctx, registry, config, jsonMapper) -> KeycloakAdminResteasyClientRecorder
                        .setClientProvider(registry, config, jsonMapper.mapper()));
    }

    @BuildStep(onlyIf = KeycloakAdminClientInjectionEnabled.class)
    public void registerKeycloakAdminClientBeans(ServiceRegistrar serviceRegistrar,
            BuildProducer<SyntheticBeanBuildItem> syntheticBeanBuildItemBuildProducer) {
        serviceRegistrar
                .forService("io.quarkus.keycloak-admin-resteasy-client.validate-config")
                .atPhase(Phase.INIT)
                .require(KeycloakAdminClientConfig.class)
                .onStart((ctx, config) -> KeycloakAdminClientConfigUtil.validate(config));
        syntheticBeanBuildItemBuildProducer.produce(SyntheticBeanBuildItem
                .configure(Keycloak.class)
                // use @RequestScoped as we don't want to keep client connection open too long
                .scope(RequestScoped.class)
                .setRuntimeInit()
                .reserve(true)
                .priority(0)
                .unremovable()
                .creator(KeycloakAdminClientCreator.class)
                .addInjectionPoint(Type.create(KeycloakAdminClientConfig.class))
                .autoClose(true)
                .done());
    }
}
