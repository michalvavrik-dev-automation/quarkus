package io.quarkus.keycloak.admin.client.common.deployment;

import io.quarkus.builder.item.SimpleBuildItem;

/**
 * Describes how the Keycloak admin client extensions must configure Jackson for the Keycloak representations
 * available on the runtime classpath.
 */
public final class KeycloakAdminClientJacksonBuildItem extends SimpleBuildItem {

    private final boolean bridgeJackson2JsonNode;

    KeycloakAdminClientJacksonBuildItem(boolean bridgeJackson2JsonNode) {
        this.bridgeJackson2JsonNode = bridgeJackson2JsonNode;
    }

    /**
     * @return {@code true} if the Jackson 2 variant of the Keycloak representations ({@code keycloak-client-common-synced})
     *         is on the runtime classpath, in which case the admin client (de)serializes representations whose fields
     *         are Jackson 2 {@code JsonNode}s and must bridge them
     */
    public boolean bridgeJackson2JsonNode() {
        return bridgeJackson2JsonNode;
    }
}
