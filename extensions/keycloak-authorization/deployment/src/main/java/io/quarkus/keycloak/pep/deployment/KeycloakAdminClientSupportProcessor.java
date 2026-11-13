package io.quarkus.keycloak.pep.deployment;

import java.util.HashSet;
import java.util.Set;
import java.util.TreeSet;

import org.jboss.logging.Logger;

import io.quarkus.bootstrap.model.ApplicationModel;
import io.quarkus.core.Phase;
import io.quarkus.core.deployment.service.ServiceRegistrar;
import io.quarkus.deployment.Capabilities;
import io.quarkus.deployment.Capability;
import io.quarkus.deployment.annotations.BuildProducer;
import io.quarkus.deployment.annotations.BuildStep;
import io.quarkus.deployment.builditem.RemovedResourceBuildItem;
import io.quarkus.deployment.pkg.builditem.CurateOutcomeBuildItem;
import io.quarkus.keycloak.admin.client.common.runtime.KeycloakAdminClientJsonMapper;
import io.quarkus.keycloak.pep.runtime.KeycloakAdminClientJackson2Bridge;
import io.quarkus.maven.dependency.ResolvedDependency;

/**
 * Support for the Keycloak admin client extensions.
 * <p>
 * This extension brings the Jackson 2 variant of the Keycloak representations ({@code keycloak-client-common-synced},
 * used by the Keycloak authorization client and policy enforcer) while the Keycloak admin client extensions use the
 * Jackson 3 variant ({@code keycloak-client-common-synced-jackson3}). Both contain the same classes, but a few of them
 * differ: the Jackson 2 representations hold Jackson 2 {@code JsonNode} fields and the Keycloak annotations like
 * {@code @StringOrArray} carry Jackson 2 meta-annotations.
 * <p>
 * When both variants are on the classpath, the Jackson 2 variant must win, because Jackson 2 only applies the Keycloak
 * (de)serializers through these meta-annotations (the policy enforcer would fail to parse an access token with a single
 * audience otherwise), while the Jackson 3 admin client handles the Jackson 2 variant of the representations thanks to
 * its annotation introspector and the {@code JsonNode} bridge. In dev and test mode, this is achieved by the lesser
 * classloading priority of the Jackson 3 variant declared in the extension descriptor; in a packaged application (and so
 * in native mode), the duplicated classes are removed from the Jackson 3 variant.
 */
public class KeycloakAdminClientSupportProcessor {

    private static final Logger LOG = Logger.getLogger(KeycloakAdminClientSupportProcessor.class);

    private static final String KEYCLOAK_GROUP_ID = "org.keycloak";
    private static final String JACKSON2_REPRESENTATIONS_ARTIFACT_ID = "keycloak-client-common-synced";
    private static final String JACKSON3_REPRESENTATIONS_ARTIFACT_ID = "keycloak-client-common-synced-jackson3";

    @BuildStep
    void adminClientJsonMapper(Capabilities capabilities, ServiceRegistrar serviceRegistrar,
            CurateOutcomeBuildItem curateOutcome, BuildProducer<RemovedResourceBuildItem> removedResources) {
        if (!capabilities.isPresent(Capability.KEYCLOAK_ADMIN_CLIENT)) {
            return;
        }
        ApplicationModel applicationModel = curateOutcome.getApplicationModel();
        ResolvedDependency jackson2Representations = findRuntimeDependency(applicationModel,
                JACKSON2_REPRESENTATIONS_ARTIFACT_ID);
        ResolvedDependency jackson3Representations = findRuntimeDependency(applicationModel,
                JACKSON3_REPRESENTATIONS_ARTIFACT_ID);
        if (jackson2Representations != null && jackson3Representations != null) {
            Set<String> duplicatedClasses = new TreeSet<>(classes(jackson3Representations));
            duplicatedClasses.retainAll(classes(jackson2Representations));
            if (!duplicatedClasses.isEmpty()) {
                LOG.debugf("Removing %d classes duplicated in '%s' from '%s'", duplicatedClasses.size(),
                        jackson2Representations.toCompactCoords(), jackson3Representations.toCompactCoords());
                removedResources.produce(new RemovedResourceBuildItem(jackson3Representations.getKey(), duplicatedClasses));
            }
        }
        serviceRegistrar
                .forService(KeycloakAdminClientJsonMapper.class)
                .atPhase(Phase.INIT)
                .onStart(ctx -> KeycloakAdminClientJackson2Bridge.jsonMapper());
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
