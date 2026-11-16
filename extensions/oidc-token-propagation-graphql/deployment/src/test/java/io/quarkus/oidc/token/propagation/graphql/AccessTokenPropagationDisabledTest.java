package io.quarkus.oidc.token.propagation.graphql;

import static org.hamcrest.Matchers.equalTo;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import io.quarkus.test.QuarkusExtensionTest;
import io.quarkus.test.common.QuarkusTestResource;
import io.quarkus.test.oidc.client.OidcTestClient;
import io.quarkus.test.oidc.server.OidcWiremockTestResource;
import io.restassured.RestAssured;

@QuarkusTestResource(value = OidcWiremockTestResource.class, restrictToAnnotatedClass = true)
public class AccessTokenPropagationDisabledTest {

    static final OidcTestClient client = new OidcTestClient();

    @RegisterExtension
    static final QuarkusExtensionTest test = new QuarkusExtensionTest()
            .withApplicationRoot((jar) -> jar
                    .addClasses(PublicGraphQLApi.class, PropagationTypesafeGraphQLClient.class, FrontendResource.class))
            .overrideConfigKey("quarkus.smallrye-graphql-client-oidc-token-propagation.enabled", "false")
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
    public void testAccessTokenIsNotPropagated() {
        RestAssured.given().auth().oauth2(client.getAccessToken("alice", "alice"))
                .when().get("/frontend/me")
                .then()
                .statusCode(200)
                .body(equalTo("anonymous"));
    }
}
