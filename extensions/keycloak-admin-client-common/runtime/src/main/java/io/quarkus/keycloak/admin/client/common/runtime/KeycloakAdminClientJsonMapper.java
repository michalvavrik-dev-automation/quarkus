package io.quarkus.keycloak.admin.client.common.runtime;

import tools.jackson.databind.json.JsonMapper;

/**
 * Provides the Jackson 3 {@link JsonMapper} used by the Keycloak admin client extensions to (de)serialize
 * the Keycloak representations.
 */
public final class KeycloakAdminClientJsonMapper {

    private KeycloakAdminClientJsonMapper() {
    }

    /**
     * @param bridgeJackson2JsonNode whether the Jackson 2 variant of the Keycloak representations is on the classpath,
     *        in which case the Jackson 2 {@code JsonNode} fields of the representations must be bridged, see
     *        {@link Jackson2JsonNodeModule}
     * @return the mapper of the Keycloak admin client, the same instance is returned when no bridge is required
     */
    public static JsonMapper create(boolean bridgeJackson2JsonNode) {
        JsonMapper keycloakMapper = keycloakMapper();
        if (!bridgeJackson2JsonNode) {
            return keycloakMapper;
        }
        return keycloakMapper.rebuild().addModule(new Jackson2JsonNodeModule()).build();
    }

    /**
     * Returns {@code org.keycloak.admin.client.jackson3.Jackson3MapperHolder#MAPPER}, the mapper of the Keycloak admin client.
     * The holder is package-private, so the body of this method is generated at build time by
     * {@code KeycloakAdminClientProcessor}.
     * TODO: make the holder public in Keycloak, then call it directly and drop the generation
     */
    static native JsonMapper keycloakMapper();
}
