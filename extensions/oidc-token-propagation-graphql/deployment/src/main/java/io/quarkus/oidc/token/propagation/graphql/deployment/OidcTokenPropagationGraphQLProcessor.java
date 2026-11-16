package io.quarkus.oidc.token.propagation.graphql.deployment;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.BooleanSupplier;

import jakarta.enterprise.inject.spi.DeploymentException;

import org.jboss.jandex.AnnotationTarget;
import org.jboss.jandex.AnnotationValue;
import org.jboss.jandex.ClassInfo;
import org.jboss.jandex.DotName;

import io.quarkus.core.deployment.service.ServiceRegistrar;
import io.quarkus.deployment.Feature;
import io.quarkus.deployment.annotations.BuildProducer;
import io.quarkus.deployment.annotations.BuildStep;
import io.quarkus.deployment.builditem.FeatureBuildItem;
import io.quarkus.oidc.client.filter.OidcClientFilter;
import io.quarkus.oidc.token.propagation.common.deployment.AccessTokenInstanceBuildItem;
import io.quarkus.oidc.token.propagation.graphql.runtime.GraphQLAccessTokenProvider;
import io.quarkus.smallrye.graphql.client.deployment.GraphQLClientAuthorizationHeaderBuildItem;
import io.quarkus.smallrye.graphql.client.deployment.GraphQLClientConfigInitializedBuildItem;

class OidcTokenPropagationGraphQLProcessor {

    private static final DotName GRAPHQL_CLIENT_API = DotName
            .createSimple("io.smallrye.graphql.client.typesafe.api.GraphQLClientApi");

    private static final DotName OIDC_CLIENT_FILTER = DotName.createSimple(OidcClientFilter.class);

    @BuildStep
    FeatureBuildItem feature() {
        return new FeatureBuildItem(Feature.SMALLRYE_GRAPHQL_CLIENT_OIDC_TOKEN_PROPAGATION);
    }

    @BuildStep(onlyIf = IsEnabled.class)
    void propagateAccessTokens(List<AccessTokenInstanceBuildItem> accessTokenInstances,
            ServiceRegistrar serviceRegistrar,
            BuildProducer<GraphQLClientAuthorizationHeaderBuildItem> authorizationHeaderProducer) {
        Map<String, AccessTokenInstanceBuildItem> configKeyToAccessToken = new HashMap<>();
        Map<String, String> configKeyToExchangeOidcClient = new HashMap<>();

        for (AccessTokenInstanceBuildItem instance : accessTokenInstances) {
            AnnotationTarget annotationTarget = instance.getAnnotationTarget();
            boolean methodLevel = annotationTarget.kind() == AnnotationTarget.Kind.METHOD;
            ClassInfo graphQLClientApi = methodLevel ? annotationTarget.asMethod().declaringClass()
                    : annotationTarget.asClass();
            if (!graphQLClientApi.hasDeclaredAnnotation(GRAPHQL_CLIENT_API)) {
                // not a GraphQL typesafe client; handled by the REST token-propagation modules
                continue;
            }
            if (methodLevel) {
                throw new DeploymentException(
                        String.format("@AccessToken on method '%s' of GraphQL client '%s' is not supported; "
                                + "annotate the client interface instead.",
                                annotationTarget.asMethod().name(), instance.targetClass()));
            }
            if (graphQLClientApi.hasDeclaredAnnotation(OIDC_CLIENT_FILTER)) {
                throw new DeploymentException(
                        String.format("GraphQL client '%s' is annotated with both @AccessToken and @OidcClientFilter; "
                                + "both mechanisms set the Authorization header, so only one of them can be used "
                                + "on the same client.",
                                instance.targetClass()));
            }
            String configKey = resolveConfigKey(graphQLClientApi);
            AccessTokenInstanceBuildItem previousInstance = configKeyToAccessToken.put(configKey, instance);
            if (previousInstance != null && (previousInstance.exchangeTokenActivated() != instance.exchangeTokenActivated()
                    || !previousInstance.getClientName().equals(instance.getClientName()))) {
                // the GraphQL clients with the same configuration key share the Authorization header
                throw new DeploymentException(
                        String.format("GraphQL clients '%s' and '%s' share the configuration key '%s', therefore their "
                                + "@AccessToken annotations must have the same 'exchangeTokenClient' attribute value.",
                                previousInstance.targetClass(), instance.targetClass(), configKey));
            }
            if (instance.exchangeTokenActivated()) {
                configKeyToExchangeOidcClient.put(configKey, instance.getClientName());
            }
        }

        if (configKeyToAccessToken.isEmpty()) {
            return;
        }

        for (String configKey : configKeyToAccessToken.keySet()) {
            authorizationHeaderProducer
                    .produce(new GraphQLClientAuthorizationHeaderBuildItem(configKey, "the @AccessToken annotation"));
        }

        Set<String> propagateConfigKeys = Set.copyOf(configKeyToAccessToken.keySet());
        Map<String, String> exchangeOidcClients = Map.copyOf(configKeyToExchangeOidcClient);
        serviceRegistrar.forService("io.quarkus.oidc-token-propagation-graphql.propagate-access-tokens")
                .afterBuildItem(GraphQLClientConfigInitializedBuildItem.class)
                // GraphQL clients must propagate access tokens before the application starts using them
                .before("io.quarkus.arc.startup-event")
                .onStart(ctx -> GraphQLAccessTokenProvider.propagateAccessTokens(ctx, propagateConfigKeys,
                        exchangeOidcClients));
    }

    private static String resolveConfigKey(ClassInfo graphQLClientApi) {
        AnnotationValue configKeyValue = graphQLClientApi.declaredAnnotation(GRAPHQL_CLIENT_API).value("configKey");
        String configKey = configKeyValue != null ? configKeyValue.asString() : null;
        return (configKey != null && !configKey.isEmpty()) ? configKey : graphQLClientApi.name().toString();
    }

    static class IsEnabled implements BooleanSupplier {
        OidcTokenPropagationGraphQLBuildTimeConfig config;

        public boolean getAsBoolean() {
            return config.enabled();
        }
    }
}
