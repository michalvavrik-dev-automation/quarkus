package io.quarkus.keycloak.admin.client.common.deployment;

import java.util.HashSet;
import java.util.Set;
import java.util.TreeSet;

import org.jboss.logging.Logger;

import io.quarkus.bootstrap.model.ApplicationModel;
import io.quarkus.deployment.annotations.BuildProducer;
import io.quarkus.deployment.annotations.BuildStep;
import io.quarkus.deployment.builditem.RemovedResourceBuildItem;
import io.quarkus.deployment.builditem.nativeimage.ReflectiveClassBuildItem;
import io.quarkus.deployment.builditem.nativeimage.RuntimeInitializedClassBuildItem;
import io.quarkus.deployment.builditem.nativeimage.ServiceProviderBuildItem;
import io.quarkus.deployment.pkg.builditem.CurateOutcomeBuildItem;
import io.quarkus.keycloak.admin.client.common.runtime.KeycloakAdminClientJsonMapper;
import io.quarkus.maven.dependency.ResolvedDependency;

public class KeycloakAdminClientProcessor {

    private static final Logger LOG = Logger.getLogger(KeycloakAdminClientProcessor.class);

    private static final String KEYCLOAK_GROUP_ID = "org.keycloak";
    /**
     * Jackson 2 variant of the Keycloak representations, used by the Keycloak authorization client and policy enforcer.
     */
    private static final String JACKSON2_REPRESENTATIONS_ARTIFACT_ID = "keycloak-client-common-synced";
    /**
     * Jackson 3 variant of the Keycloak representations, used by the Jackson 3 Keycloak admin client.
     */
    private static final String JACKSON3_REPRESENTATIONS_ARTIFACT_ID = "keycloak-client-common-synced-jackson3";

    private static final String KEYCLOAK_JSON_MAPPER_SPI = "org.keycloak.json.KeycloakJsonMapper";
    private static final String KEYCLOAK_RAW_JSON_VALUE_SUPPORT_SPI = "org.keycloak.json.RawJsonValueSupport";

    @BuildStep
    public void nativeImage(BuildProducer<RuntimeInitializedClassBuildItem> runtimeInit,
            BuildProducer<ServiceProviderBuildItem> serviceProviders,
            BuildProducer<ReflectiveClassBuildItem> reflectiveClasses) {
        runtimeInit.produce(new RuntimeInitializedClassBuildItem("org.keycloak.common.util.SecretGenerator"));

        // the Keycloak representations resolve their JSON mapper (and the RawJsonValue support) through the ServiceLoader
        serviceProviders.produce(ServiceProviderBuildItem.allProvidersFromClassPath(KEYCLOAK_JSON_MAPPER_SPI));
        serviceProviders.produce(ServiceProviderBuildItem.allProvidersFromClassPath(KEYCLOAK_RAW_JSON_VALUE_SUPPORT_SPI));

        // Jackson 3 (de)serializers instantiated reflectively through the Keycloak annotation introspector,
        // see org.keycloak.admin.client.jackson3.KeycloakAnnotationIntrospector3
        reflectiveClasses.produce(ReflectiveClassBuildItem.builder(
                "org.keycloak.admin.client.jackson3.StringOrArrayDeserializer3",
                "org.keycloak.admin.client.jackson3.StringOrArraySerializer3",
                "org.keycloak.admin.client.jackson3.StringListMapDeserializer3",
                "org.keycloak.admin.client.jackson3.MultivaluedHashMapValueDeserializer3",
                "org.keycloak.admin.client.jackson3.MultivaluedHashMapValueSerializer3",
                "org.keycloak.admin.client.jackson3.ResourceTypeMapDeserializer3")
                .reason(getClass().getName())
                .constructors().build());
        // the mapper configured by the Keycloak admin client is accessed reflectively, see KeycloakAdminClientJsonMapper
        reflectiveClasses.produce(ReflectiveClassBuildItem.builder(KeycloakAdminClientJsonMapper.KEYCLOAK_MAPPER_HOLDER)
                .reason(getClass().getName())
                .fields().build());
    }

    /**
     * The Jackson 2 variant of the Keycloak representations (used by the Keycloak authorization client and
     * policy enforcer, Dev Services for Keycloak and the Keycloak test framework) and the Jackson 3 variant
     * (used by the Keycloak admin client) contain the same classes, but a few of them differ: the Jackson 2
     * representations hold Jackson 2 {@code JsonNode} fields and the Keycloak annotations like {@code @StringOrArray}
     * carry Jackson 2 meta-annotations.
     * <p>
     * When both variants are on the runtime classpath, the Jackson 2 variant must win, because Jackson 2 only
     * applies the Keycloak (de)serializers through these meta-annotations (e.g. the policy enforcer would fail to parse
     * an access token with a single audience otherwise), while the Jackson 3 admin client handles the Jackson 2
     * variant of the representations thanks to its annotation introspector and the {@code JsonNode} bridge.
     * <p>
     * In dev and test mode, this is achieved by the lesser classloading priority of the Jackson 3 variant declared
     * in the extension descriptor; in a packaged application (and so in native mode), the duplicated classes are
     * removed from the Jackson 3 variant.
     */
    @BuildStep
    KeycloakAdminClientJacksonBuildItem preferJackson2Representations(CurateOutcomeBuildItem curateOutcome,
            BuildProducer<RemovedResourceBuildItem> removedResources) {
        ApplicationModel applicationModel = curateOutcome.getApplicationModel();
        ResolvedDependency jackson2Representations = findRuntimeDependency(applicationModel,
                JACKSON2_REPRESENTATIONS_ARTIFACT_ID);
        if (jackson2Representations == null) {
            return new KeycloakAdminClientJacksonBuildItem(false);
        }
        ResolvedDependency jackson3Representations = findRuntimeDependency(applicationModel,
                JACKSON3_REPRESENTATIONS_ARTIFACT_ID);
        if (jackson3Representations != null) {
            Set<String> duplicatedClasses = new TreeSet<>(classes(jackson3Representations));
            duplicatedClasses.retainAll(classes(jackson2Representations));
            if (!duplicatedClasses.isEmpty()) {
                LOG.debugf("Removing %d classes duplicated in '%s' from '%s'", duplicatedClasses.size(),
                        jackson2Representations.toCompactCoords(), jackson3Representations.toCompactCoords());
                removedResources.produce(new RemovedResourceBuildItem(jackson3Representations.getKey(), duplicatedClasses));
            }
        }
        return new KeycloakAdminClientJacksonBuildItem(true);
    }

    private static ResolvedDependency findRuntimeDependency(ApplicationModel applicationModel, String artifactId) {
        for (ResolvedDependency dependency : applicationModel.getRuntimeDependencies()) {
            if (KEYCLOAK_GROUP_ID.equals(dependency.getGroupId()) && artifactId.equals(dependency.getArtifactId())) {
                return dependency;
            }
        }
        return null;
    }

    private static Set<String> classes(ResolvedDependency dependency) {
        Set<String> classes = new HashSet<>();
        dependency.getContentTree().walk(visit -> {
            String path = visit.getRelativePath("/");
            if (path.endsWith(".class")) {
                classes.add(path);
            }
        });
        return classes;
    }
}
