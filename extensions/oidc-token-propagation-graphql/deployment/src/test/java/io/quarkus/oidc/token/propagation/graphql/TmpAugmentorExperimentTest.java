package io.quarkus.oidc.token.propagation.graphql;

import java.util.function.Supplier;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import io.quarkus.security.identity.AuthenticationRequestContext;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.security.identity.SecurityIdentityAugmentor;
import io.quarkus.security.runtime.QuarkusSecurityIdentity;
import io.quarkus.test.QuarkusExtensionTest;
import io.quarkus.test.common.QuarkusTestResource;
import io.quarkus.test.oidc.client.OidcTestClient;
import io.quarkus.test.oidc.server.OidcWiremockTestResource;
import io.restassured.RestAssured;
import io.restassured.config.HttpClientConfig;
import io.restassured.config.RestAssuredConfig;
import io.smallrye.mutiny.Uni;

@QuarkusTestResource(OidcWiremockTestResource.class)
public class TmpAugmentorExperimentTest {

    static final OidcTestClient client = new OidcTestClient();

    @RegisterExtension
    static final QuarkusExtensionTest test = new QuarkusExtensionTest()
            .withApplicationRoot((jar) -> jar
                    .addClasses(PublicGraphQLApi.class, PropagationTypesafeGraphQLClient.class, FrontendResource.class,
                            Augmentor.class))
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
    public void experiment() {
        try {
            var response = RestAssured.given()
                    .config(RestAssuredConfig.config().httpClient(HttpClientConfig.httpClientConfig()
                            .setParam("http.socket.timeout", 20000).setParam("http.connection.timeout", 20000)))
                    .auth().oauth2(client.getAccessToken("alice", "alice"))
                    .when().get("/frontend/me");
            System.out.println("EXPERIMENT-RESULT status=" + response.statusCode() + " body="
                    + response.asString().lines().limit(3).reduce("", (a, b) -> a + " | " + b));
        } catch (Throwable t) {
            System.out.println("EXPERIMENT-RESULT exception=" + t);
        }
    }

    @ApplicationScoped
    public static class Augmentor implements SecurityIdentityAugmentor {

        @Inject
        PropagationTypesafeGraphQLClient graphQLClient;

        @Override
        public Uni<SecurityIdentity> augment(SecurityIdentity identity, AuthenticationRequestContext context) {
            if (identity.isAnonymous() || identity.hasRole("augmented")) {
                return Uni.createFrom().item(identity);
            }
            return context.runBlocking(new Supplier<SecurityIdentity>() {
                @Override
                public SecurityIdentity get() {
                    String me;
                    try {
                        me = graphQLClient.me();
                    } catch (Throwable t) {
                        System.out.println("EXPERIMENT-AUGMENTOR exception=" + t);
                        throw t;
                    }
                    System.out.println("EXPERIMENT-AUGMENTOR me=" + me);
                    return QuarkusSecurityIdentity.builder(identity).addRole("augmented").build();
                }
            });
        }
    }
}
