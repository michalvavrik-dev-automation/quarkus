package io.quarkus.keycloak.admin.client.common.deployment;

import java.lang.reflect.Modifier;
import java.util.HashSet;
import java.util.Set;
import java.util.TreeSet;

import org.jboss.logging.Logger;

import io.quarkus.bootstrap.model.ApplicationModel;
import io.quarkus.core.Phase;
import io.quarkus.core.deployment.service.ServiceRegistrar;
import io.quarkus.deployment.annotations.BuildProducer;
import io.quarkus.deployment.annotations.BuildStep;
import io.quarkus.deployment.builditem.BytecodeTransformerBuildItem;
import io.quarkus.deployment.builditem.RemovedResourceBuildItem;
import io.quarkus.deployment.builditem.nativeimage.ReflectiveClassBuildItem;
import io.quarkus.deployment.builditem.nativeimage.RuntimeInitializedClassBuildItem;
import io.quarkus.deployment.builditem.nativeimage.ServiceProviderBuildItem;
import io.quarkus.deployment.pkg.builditem.CurateOutcomeBuildItem;
import io.quarkus.gizmo.ClassTransformer;
import io.quarkus.gizmo.FieldDescriptor;
import io.quarkus.gizmo.MethodCreator;
import io.quarkus.gizmo.MethodDescriptor;
import io.quarkus.keycloak.admin.client.common.runtime.KeycloakAdminClientJsonMapper;
import io.quarkus.maven.dependency.ResolvedDependency;
import tools.jackson.databind.json.JsonMapper;

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

    /**
     * Name of the {@link JsonMapper} service the Keycloak admin client extensions (de)serialize the Keycloak representations
     * with.
     */
    public static final String JSON_MAPPER_SERVICE = "io.quarkus.keycloak-admin-client.json-mapper";

    private static final String KEYCLOAK_JSON_MAPPER_SPI = "org.keycloak.json.KeycloakJsonMapper";
    private static final String KEYCLOAK_MAPPER_HOLDER = "org.keycloak.admin.client.jackson3.Jackson3MapperHolder";
    private static final String KEYCLOAK_MAPPER_FIELD = "MAPPER";
    private static final String KEYCLOAK_RAW_JSON_VALUE_SUPPORT_SPI = "org.keycloak.json.RawJsonValueSupport";

    @BuildStep
    public void nativeImage(BuildProducer<RuntimeInitializedClassBuildItem> runtimeInit,
            BuildProducer<ServiceProviderBuildItem> serviceProviders,
            BuildProducer<ReflectiveClassBuildItem> reflectiveClasses) {
        runtimeInit.produce(new RuntimeInitializedClassBuildItem("org.keycloak.common.util.SecretGenerator"));

        // the Keycloak representations resolve their JSON mapper (and the RawJsonValue support) through the ServiceLoader
        serviceProviders.produce(ServiceProviderBuildItem.allProvidersFromClassPath(KEYCLOAK_JSON_MAPPER_SPI));
        serviceProviders.produce(ServiceProviderBuildItem.allProvidersFromClassPath(KEYCLOAK_RAW_JSON_VALUE_SUPPORT_SPI));

        // Jackson 3 (de)serializers instantiated reflectively through the annotation introspector
        // of the Keycloak admin client mapper, see org.keycloak.admin.client.jackson3.KeycloakAnnotationIntrospector3
        reflectiveClasses.produce(ReflectiveClassBuildItem.builder(
                "org.keycloak.admin.client.jackson3.StringOrArrayDeserializer3",
                "org.keycloak.admin.client.jackson3.StringOrArraySerializer3",
                "org.keycloak.admin.client.jackson3.StringListMapDeserializer3",
                "org.keycloak.admin.client.jackson3.MultivaluedHashMapValueDeserializer3",
                "org.keycloak.admin.client.jackson3.MultivaluedHashMapValueSerializer3",
                "org.keycloak.admin.client.jackson3.ResourceTypeMapDeserializer3")
                .reason(getClass().getName())
                .constructors().build());
    }

    /**
     * Implements {@link KeycloakAdminClientJsonMapper#keycloakMapper()}: the mapper of the Keycloak admin client is held
     * by the package-private {@code Jackson3MapperHolder}, so the holder and its field are made public and the native
     * method is replaced with one returning the field.
     * <p>
     * TODO: drop once the holder is public in Keycloak
     */
    @BuildStep
    void keycloakJsonMapperAccess(BuildProducer<BytecodeTransformerBuildItem> transformers) {
        FieldDescriptor mapperField = FieldDescriptor.of(KEYCLOAK_MAPPER_HOLDER, KEYCLOAK_MAPPER_FIELD, JsonMapper.class);
        transformers.produce(new BytecodeTransformerBuildItem(KEYCLOAK_MAPPER_HOLDER, (className, classVisitor) -> {
            ClassTransformer transformer = new ClassTransformer(className);
            transformer.addModifiers(Modifier.PUBLIC);
            transformer.modifyField(mapperField).addModifiers(Modifier.PUBLIC);
            return transformer.applyTo(classVisitor);
        }));
        transformers.produce(new BytecodeTransformerBuildItem(KeycloakAdminClientJsonMapper.class.getName(),
                (className, classVisitor) -> {
                    ClassTransformer transformer = new ClassTransformer(className);
                    MethodDescriptor keycloakMapper = MethodDescriptor.ofMethod(KeycloakAdminClientJsonMapper.class,
                            "keycloakMapper", JsonMapper.class);
                    // the native method is removed first as methods are created in 'visitEnd'
                    // while the method is removed by simply being ignored in 'visitMethod'
                    transformer.removeMethod(keycloakMapper);
                    try (MethodCreator method = transformer.addMethod(keycloakMapper)) {
                        method.setModifiers(Modifier.STATIC);
                        method.returnValue(method.readStaticField(mapperField));
                    }
                    return transformer.applyTo(classVisitor);
                }));
    }

    /**
     * Registers the {@link JsonMapper} service used by the Keycloak admin client extensions, see
     * {@link #JSON_MAPPER_SERVICE}: the mapper of the Keycloak admin client, extended with the bridge for the Jackson 2
     * {@code JsonNode} fields when the Jackson 2 variant of the Keycloak representations is on the runtime classpath.
     * <p>
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
    void jsonMapper(ServiceRegistrar serviceRegistrar, CurateOutcomeBuildItem curateOutcome,
            BuildProducer<RemovedResourceBuildItem> removedResources) {
        ApplicationModel applicationModel = curateOutcome.getApplicationModel();
        ResolvedDependency jackson2Representations = findRuntimeDependency(applicationModel,
                JACKSON2_REPRESENTATIONS_ARTIFACT_ID);
        if (jackson2Representations == null) {
            serviceRegistrar
                    .forService(JsonMapper.class, JSON_MAPPER_SERVICE)
                    .atPhase(Phase.INIT)
                    .onStart(ctx -> KeycloakAdminClientJsonMapper.keycloak());
            return;
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
        serviceRegistrar
                .forService(JsonMapper.class, JSON_MAPPER_SERVICE)
                .atPhase(Phase.INIT)
                .onStart(ctx -> KeycloakAdminClientJsonMapper.bridgingJackson2JsonNode());
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
