package io.quarkus.oidc.client.graphql;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.fail;

import org.eclipse.microprofile.graphql.Query;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import io.quarkus.oidc.token.propagation.common.AccessToken;
import io.quarkus.runtime.configuration.ConfigurationException;
import io.quarkus.test.QuarkusExtensionTest;
import io.smallrye.graphql.client.typesafe.api.GraphQLClientApi;

public class OidcClientNameAndAccessTokenConflictTest {

    @RegisterExtension
    static final QuarkusExtensionTest test = new QuarkusExtensionTest()
            .withApplicationRoot((jar) -> jar.addClasses(TokenPropagationGraphQLClient.class))
            .overrideConfigKey("quarkus.oidc-client-graphql.token-propagation.client-name", "graphql-oidc-client")
            .assertException(t -> assertThat(t)
                    .isInstanceOf(ConfigurationException.class)
                    .hasMessageContaining("The 'graphql-oidc-client' OIDC client has been configured for the "
                            + "'token-propagation' GraphQL client")
                    .hasMessageContaining("'quarkus.oidc-client-graphql.\"token-propagation\".client-name'")
                    .hasMessageContaining("is already provided by the @AccessToken annotation"));

    @Test
    public void shouldNotBeInvoked() {
        fail("This method should not be invoked");
    }

    @GraphQLClientApi(configKey = "token-propagation")
    @AccessToken
    public interface TokenPropagationGraphQLClient {

        @Query
        String me();
    }
}
