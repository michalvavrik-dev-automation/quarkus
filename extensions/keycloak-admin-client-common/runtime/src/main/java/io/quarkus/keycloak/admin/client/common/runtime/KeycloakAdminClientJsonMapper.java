package io.quarkus.keycloak.admin.client.common.runtime;

import tools.jackson.databind.json.JsonMapper;

/**
 * Provides the Jackson 3 {@link JsonMapper} used by the Keycloak admin client extensions to (de)serialize
 * the Keycloak representations. Which one is used is decided at build time, see {@code KeycloakAdminClientProcessor}.
 */
public final class KeycloakAdminClientJsonMapper {

    private KeycloakAdminClientJsonMapper() {
    }

    /**
     * @return the mapper of the Keycloak admin client
     */
    public static JsonMapper keycloak() {
        return keycloakMapper();
    }

    /**
     * @return the mapper of the Keycloak admin client extended with the bridge for the Jackson 2 {@code JsonNode} fields
     *         of the Jackson 2 variant of the Keycloak representations, see {@link Jackson2JsonNodeModule}
     */
    public static JsonMapper bridgingJackson2JsonNode() {
        return keycloakMapper().rebuild().addModule(new Jackson2JsonNodeModule()).build();
    }

    /**
     * Returns {@code org.keycloak.admin.client.jackson3.Jackson3MapperHolder#MAPPER}, the mapper of the Keycloak admin client.
     * The holder is package-private, so the body of this method is generated at build time by
     * {@code KeycloakAdminClientProcessor}.
     * TODO: make the holder public in Keycloak, then call it directly and drop the generation
     */
    static native JsonMapper keycloakMapper();
}
