package io.quarkus.it.oidc.dev.services;

import static org.hamcrest.Matchers.equalTo;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Test;

import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.oidc.client.OidcTestClient;
import io.restassured.RestAssured;

@QuarkusTest
public class OidcGraphQLClientTest {

    static final OidcTestClient oidcTestClient = new OidcTestClient();

    @AfterAll
    public static void close() {
        oidcTestClient.close();
    }

    @Test
    void defaultOidcClient() {
        RestAssured.when().get("/oidc-graphql-test/default")
                .then()
                .statusCode(200)
                .body(equalTo("alice"));
    }

    @Test
    void namedOidcClient() {
        RestAssured.when().get("/oidc-graphql-test/named")
                .then()
                .statusCode(200)
                .body(equalTo("alice"));
    }

    @Test
    void tokenPropagation() {
        // OIDC clients acquire tokens for 'alice', so 'bob' is only returned if the incoming token is propagated
        RestAssured.given()
                .auth().oauth2(oidcTestClient.getAccessToken("bob", "bob"))
                .when().get("/oidc-graphql-test/token-propagation")
                .then()
                .statusCode(200)
                .body(equalTo("bob"));
    }
}
