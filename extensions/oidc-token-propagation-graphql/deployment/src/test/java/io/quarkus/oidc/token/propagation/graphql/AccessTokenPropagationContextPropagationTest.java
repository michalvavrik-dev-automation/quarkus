package io.quarkus.oidc.token.propagation.graphql;

import static org.hamcrest.Matchers.equalTo;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.function.Supplier;

import jakarta.inject.Inject;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;

import org.eclipse.microprofile.context.ManagedExecutor;
import org.eclipse.microprofile.context.ThreadContext;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import io.quarkus.security.Authenticated;
import io.quarkus.test.QuarkusExtensionTest;
import io.quarkus.test.common.QuarkusTestResource;
import io.quarkus.test.oidc.client.OidcTestClient;
import io.quarkus.test.oidc.server.OidcWiremockTestResource;
import io.restassured.RestAssured;

@QuarkusTestResource(OidcWiremockTestResource.class)
public class AccessTokenPropagationContextPropagationTest {

    static final OidcTestClient client = new OidcTestClient();

    @RegisterExtension
    static final QuarkusExtensionTest test = new QuarkusExtensionTest()
            .withApplicationRoot((jar) -> jar
                    .addClasses(ProtectedGraphQLApi.class, PropagationTypesafeGraphQLClient.class,
                            ManagedExecutorFrontendResource.class))
            .withConfiguration(
                    """
                            quarkus.oidc.auth-server-url=${keycloak.url:replaced-by-test}/realms/quarkus
                            quarkus.oidc.client-id=quarkus-app
                            quarkus.oidc.credentials.secret=secret

                            quarkus.smallrye-graphql-client.propagation-client.url=http://localhost:${quarkus.http.test-port:8081}/graphql
                            """);

    @AfterAll
    public static void close() {
        client.close();
    }

    @Test
    public void testAccessTokenIsPropagatedFromManagedExecutorThread() {
        RestAssured.given().auth().oauth2(client.getAccessToken("alice", "alice"))
                .when().get("/managed-executor-frontend/me")
                .then()
                .statusCode(200)
                .body(equalTo("alice"));
    }

    @Test
    public void testAccessTokenIsPropagatedFromThreadWithPropagatedContext() {
        RestAssured.given().auth().oauth2(client.getAccessToken("alice", "alice"))
                .when().get("/managed-executor-frontend/me-thread-context")
                .then()
                .statusCode(200)
                .body(equalTo("alice"));
    }

    @Path("/managed-executor-frontend")
    @Authenticated
    public static class ManagedExecutorFrontendResource {

        @Inject
        PropagationTypesafeGraphQLClient graphQLClient;

        @Inject
        ManagedExecutor managedExecutor;

        @Inject
        ThreadContext threadContext;

        @GET
        @Path("/me-thread-context")
        public String meThreadContext() throws Exception {
            ExecutorService executor = Executors.newSingleThreadExecutor();
            try {
                // the CDI request context is propagated to a thread which is not managed by Quarkus
                return CompletableFuture.supplyAsync(threadContext.contextualSupplier(new Supplier<String>() {
                    @Override
                    public String get() {
                        return graphQLClient.me();
                    }
                }), executor).get(30, TimeUnit.SECONDS);
            } finally {
                executor.shutdownNow();
            }
        }

        @GET
        @Path("/me")
        public String me() throws Exception {
            // the CDI request context is propagated to the managed executor thread
            return managedExecutor.supplyAsync(new Supplier<String>() {
                @Override
                public String get() {
                    return graphQLClient.me();
                }
            }).get(30, TimeUnit.SECONDS);
        }
    }
}
