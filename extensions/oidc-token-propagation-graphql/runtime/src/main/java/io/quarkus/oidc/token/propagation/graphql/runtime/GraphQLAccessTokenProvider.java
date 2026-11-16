package io.quarkus.oidc.token.propagation.graphql.runtime;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;
import java.util.function.Supplier;

import org.jboss.logging.Logger;

import io.quarkus.arc.Arc;
import io.quarkus.arc.ArcContainer;
import io.quarkus.arc.InstanceHandle;
import io.quarkus.core.StartContext;
import io.quarkus.oidc.client.OidcClient;
import io.quarkus.oidc.client.OidcClients;
import io.quarkus.oidc.client.Tokens;
import io.quarkus.oidc.client.runtime.OidcClientConfig;
import io.quarkus.oidc.client.runtime.OidcClientConfig.Grant;
import io.quarkus.oidc.client.runtime.OidcClientsConfig;
import io.quarkus.oidc.client.runtime.TokensHelper;
import io.quarkus.oidc.common.runtime.OidcConstants;
import io.quarkus.runtime.configuration.ConfigurationException;
import io.quarkus.security.credential.TokenCredential;
import io.smallrye.config.Config;
import io.smallrye.graphql.client.impl.GraphQLClientConfiguration;
import io.smallrye.graphql.client.impl.GraphQLClientsConfiguration;
import io.smallrye.mutiny.Uni;

/**
 * Provides the {@code Authorization} header value for a GraphQL client by propagating the access token of the current
 * {@link TokenCredential}. If the token exchange is activated, the access token is exchanged before it is propagated.
 */
public final class GraphQLAccessTokenProvider {

    private static final Logger LOG = Logger.getLogger(GraphQLAccessTokenProvider.class);
    private static final String AUTHORIZATION = "Authorization";
    private static final String BEARER_SCHEME_WITH_SPACE = "Bearer ";

    private final String graphQLClientKey;
    private final boolean exchangeToken;
    // empty for the default OIDC client, only used if the token exchange is activated
    private final String oidcClientName;
    private volatile TokenExchange tokenExchange;

    private GraphQLAccessTokenProvider(String graphQLClientKey, boolean exchangeToken, String oidcClientName) {
        this.graphQLClientKey = graphQLClientKey;
        this.exchangeToken = exchangeToken;
        this.oidcClientName = oidcClientName;
    }

    /**
     * Makes the GraphQL clients propagate the current access token as the {@code Authorization} header value.
     *
     * @param startContext start context
     * @param graphQLClientKeys configuration keys of the GraphQL clients which propagate the access token
     * @param tokenExchangeOidcClients configuration keys of the GraphQL clients which exchange the access token before it is
     *        propagated, mapped to the name of the OIDC client which exchanges the token; the default OIDC client name is empty
     */
    public static void propagateAccessTokens(StartContext startContext, Set<String> graphQLClientKeys,
            Map<String, String> tokenExchangeOidcClients) {
        GraphQLClientsConfiguration clientsConfiguration = GraphQLClientsConfiguration.getInstance();
        Map<String, Uni<String>> authorizationHeaders = new HashMap<>();
        for (String graphQLClientKey : graphQLClientKeys) {
            GraphQLAccessTokenProvider provider = new GraphQLAccessTokenProvider(graphQLClientKey,
                    tokenExchangeOidcClients.containsKey(graphQLClientKey), tokenExchangeOidcClients.get(graphQLClientKey));
            Uni<String> authorizationHeader = provider.getAuthorizationHeader();
            clientsConfiguration.getClient(graphQLClientKey).getDynamicHeaders().put(AUTHORIZATION, authorizationHeader);
            authorizationHeaders.put(graphQLClientKey, authorizationHeader);
        }
        // the GraphQL clients configuration can outlive the application, for example in the dev mode
        startContext.onStop(new Runnable() {
            @Override
            public void run() {
                for (Map.Entry<String, Uni<String>> authorizationHeader : authorizationHeaders.entrySet()) {
                    GraphQLClientConfiguration clientConfiguration = clientsConfiguration.getClients()
                            .get(authorizationHeader.getKey());
                    if (clientConfiguration != null && clientConfiguration.getDynamicHeaders() != null) {
                        clientConfiguration.getDynamicHeaders().remove(AUTHORIZATION, authorizationHeader.getValue());
                    }
                }
            }
        });
    }

    private Uni<String> getAuthorizationHeader() {
        // the access token is resolved for each GraphQL client request
        return Uni.createFrom().deferred(new Supplier<Uni<? extends String>>() {
            @Override
            public Uni<String> get() {
                String accessToken = getAccessToken();
                if (exchangeToken) {
                    return getTokenExchange().exchange(accessToken);
                }
                return Uni.createFrom().item(BEARER_SCHEME_WITH_SPACE + accessToken);
            }
        });
    }

    private String getAccessToken() {
        ArcContainer container = Arc.container();
        if (container == null) {
            throw accessTokenNotAvailable("the CDI container is not available, the application may be shutting down");
        }
        try (InstanceHandle<TokenCredential> tokenCredential = container.instance(TokenCredential.class)) {
            if (!tokenCredential.isAvailable()) {
                throw accessTokenNotAvailable("there is either no TokenCredential bean or more than one such bean,"
                        + " the bean is provided by the extensions like quarkus-oidc or quarkus-smallrye-jwt");
            }
            String accessToken = tokenCredential.get().getToken();
            if (accessToken == null) {
                throw accessTokenNotAvailable("the current TokenCredential has no token,"
                        + " the current request is not authenticated with a token");
            }
            return accessToken;
        }
    }

    private IllegalStateException accessTokenNotAvailable(String reason) {
        String message = "No access token is available to propagate to the GraphQL client '%s': %s"
                .formatted(graphQLClientKey, reason);
        LOG.debug(message);
        return new IllegalStateException(message);
    }

    private TokenExchange getTokenExchange() {
        TokenExchange tokenExchange = this.tokenExchange;
        if (tokenExchange == null) {
            synchronized (this) {
                tokenExchange = this.tokenExchange;
                if (tokenExchange == null) {
                    tokenExchange = createTokenExchange();
                    this.tokenExchange = tokenExchange;
                }
            }
        }
        return tokenExchange;
    }

    private TokenExchange createTokenExchange() {
        boolean defaultOidcClient = oidcClientName.isEmpty();
        OidcClients oidcClients = Arc.requireContainer().instance(OidcClients.class).get();
        OidcClient oidcClient = null;
        if (oidcClients != null) {
            oidcClient = defaultOidcClient ? oidcClients.getClient() : oidcClients.getClient(oidcClientName);
        }
        if (oidcClient == null) {
            throw new ConfigurationException(
                    "GraphQL client '%s' requires the %s OIDC client to exchange the access token, but there is no such OIDC client"
                            .formatted(graphQLClientKey, defaultOidcClient ? "default" : "'" + oidcClientName + "'"));
        }
        OidcClientsConfig oidcClientsConfig = Config.get().getConfigMapping(OidcClientsConfig.class);
        OidcClientConfig oidcClientConfig = defaultOidcClient ? OidcClientsConfig.getDefaultClient(oidcClientsConfig)
                : oidcClientsConfig.namedClients().get(oidcClientName);
        Grant.Type grantType = oidcClientConfig.grant().type();
        final String tokenProperty;
        if (grantType == Grant.Type.EXCHANGE) {
            tokenProperty = OidcConstants.EXCHANGE_GRANT_SUBJECT_TOKEN;
        } else if (grantType == Grant.Type.JWT) {
            tokenProperty = OidcConstants.JWT_BEARER_GRANT_ASSERTION;
        } else {
            throw new ConfigurationException("Token exchange is required but OIDC client is configured "
                    + "to use the " + grantType.getGrantType() + " grantType");
        }
        return new TokenExchange(oidcClient, tokenProperty, new TokensHelper(oidcClientConfig.tokenCacheMaxSize()));
    }

    private record TokenExchange(OidcClient oidcClient, String tokenProperty, TokensHelper tokensHelper) {

        private static final Function<Tokens, String> TO_AUTHORIZATION_HEADER = new Function<Tokens, String>() {
            @Override
            public String apply(Tokens tokens) {
                return BEARER_SCHEME_WITH_SPACE + tokens.getAccessToken();
            }
        };

        private Uni<String> exchange(String accessToken) {
            // the exchanged tokens are cached for each access token
            return tokensHelper.getTokens(oidcClient, Map.of(tokenProperty, accessToken), false)
                    .map(TO_AUTHORIZATION_HEADER);
        }
    }
}
