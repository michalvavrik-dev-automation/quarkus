package io.quarkus.oidc.test;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import io.quarkus.oidc.OidcRequestContext;
import io.quarkus.oidc.OidcTenantConfig;
import io.quarkus.oidc.TenantConfigResolver;
import io.quarkus.oidc.runtime.OidcTenantConfig.ApplicationType;
import io.quarkus.oidc.runtime.OidcTenantConfig.Provider;
import io.quarkus.oidc.runtime.TenantConfigBean;
import io.quarkus.security.Authenticated;
import io.quarkus.test.QuarkusExtensionTest;
import io.smallrye.mutiny.Uni;
import io.vertx.ext.web.RoutingContext;

class TenantConfigResolverWellKnownProviderTest {

    private static final String TENANT_ID = "microsoft";

    @RegisterExtension
    static final QuarkusExtensionTest test = new QuarkusExtensionTest()
            .withApplicationRoot(jar -> jar.addClasses(ProtectedResource.class, MicrosoftTenantConfigResolver.class,
                    MockDiscoveryEndpoint.class, MockJwksEndpoint.class, MockIntrospectionEndpoint.class))
            .withConfiguration("""
                    quarkus.keycloak.devservices.enabled=false
                    """);

    @Test
    void testTenantContextUpdatedOnlyForNewTenantConfig() {
        String tenantContext = getTenantContext(false);
        // the same tenant config instance returned by the TenantConfigResolver must not update the tenant context
        given().auth().oauth2("opaque-token").get("/protected").then().statusCode(200).body(is(tenantContext));

        // a new tenant config instance returned by the TenantConfigResolver must update the tenant context
        String updatedTenantContext = getTenantContext(true);
        given().auth().oauth2("opaque-token").get("/protected").then().statusCode(200)
                .body(not(tenantContext))
                .body(is(updatedTenantContext));
    }

    private static String getTenantContext(boolean createNewTenantConfig) {
        return given().auth().oauth2("opaque-token")
                .queryParam("new-tenant-config", createNewTenantConfig)
                .get("/protected").then().statusCode(200).extract().asString();
    }

    @Path("/protected")
    @Authenticated
    public static class ProtectedResource {

        @Inject
        RoutingContext routingContext;

        @Inject
        TenantConfigBean tenantConfigBean;

        @Inject
        MicrosoftTenantConfigResolver tenantConfigResolver;

        @GET
        public String get() {
            if (tenantConfigResolver.getTenantConfig().token().issuer().isPresent()) {
                throw new IllegalStateException("Tenant config returned by the TenantConfigResolver must not be modified");
            }
            var tenantContext = tenantConfigBean.getDynamicTenant(TENANT_ID);
            OidcTenantConfig tenantConfig = tenantContext.getOidcTenantConfig();
            if (!"any".equals(tenantConfig.token().issuer().orElse(null))) {
                throw new IllegalStateException("Microsoft provider config must be applied to the tenant config");
            }
            if (tenantConfig != routingContext.get(OidcTenantConfig.class.getName())) {
                throw new IllegalStateException("Request must be authenticated with the tenant context config");
            }
            return String.valueOf(System.identityHashCode(tenantContext));
        }
    }

    @ApplicationScoped
    public static class MicrosoftTenantConfigResolver implements TenantConfigResolver {

        private volatile OidcTenantConfig tenantConfig = OidcTenantConfig.builder()
                .tenantId(TENANT_ID)
                .provider(Provider.MICROSOFT)
                .authServerUrl("http://localhost:8081/mock-oidc")
                .applicationType(ApplicationType.SERVICE)
                .clientId("quarkus-app")
                .credentials("secret")
                .build();

        @Override
        public Uni<OidcTenantConfig> resolve(RoutingContext routingContext,
                OidcRequestContext<OidcTenantConfig> requestContext) {
            if (!routingContext.normalizedPath().startsWith("/protected")) {
                return Uni.createFrom().nullItem();
            }
            if (Boolean.parseBoolean(routingContext.request().getParam("new-tenant-config"))) {
                tenantConfig = OidcTenantConfig.builder(tenantConfig).build();
            }
            return Uni.createFrom().item(tenantConfig);
        }

        public OidcTenantConfig getTenantConfig() {
            return tenantConfig;
        }
    }

    @Path("/mock-oidc/.well-known/openid-configuration")
    public static class MockDiscoveryEndpoint {

        @GET
        @Produces(MediaType.APPLICATION_JSON)
        public String discover() {
            return """
                    {
                        "issuer": "http://localhost:8081/mock-oidc",
                        "jwks_uri": "http://localhost:8081/mock-oidc/jwks",
                        "introspection_endpoint": "http://localhost:8081/mock-oidc/introspect"
                    }
                    """;
        }
    }

    @Path("/mock-oidc/jwks")
    public static class MockJwksEndpoint {

        @GET
        @Produces(MediaType.APPLICATION_JSON)
        public String jwks() {
            return "{\"keys\":[]}";
        }
    }

    @Path("/mock-oidc/introspect")
    public static class MockIntrospectionEndpoint {

        @POST
        @Produces(MediaType.APPLICATION_JSON)
        public String introspect() {
            return "{\"active\":true,\"sub\":\"test-user\",\"username\":\"test-user\"}";
        }
    }
}
