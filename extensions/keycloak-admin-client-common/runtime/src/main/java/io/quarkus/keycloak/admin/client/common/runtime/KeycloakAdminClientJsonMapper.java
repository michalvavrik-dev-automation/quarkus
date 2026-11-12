package io.quarkus.keycloak.admin.client.common.runtime;

import java.lang.reflect.Field;

import tools.jackson.databind.json.JsonMapper;

/**
 * Provides the Jackson 3 {@link JsonMapper} used by the Keycloak admin client extensions to (de)serialize
 * the Keycloak representations.
 */
public final class KeycloakAdminClientJsonMapper {

    /**
     * Package-private holder of the {@link JsonMapper} configured by the Keycloak admin client for Jackson 3.
     * Besides the inclusion and the unknown properties settings documented by Keycloak, this mapper registers the
     * annotation introspector that handles the Keycloak specific annotations like {@code @StringOrArray}, without which
     * the representations are not (de)serialized correctly. Keycloak only exposes this mapper through its
     * {@code JacksonProvider3}, which requires RESTEasy Classic, hence the reflective access.
     * <p>
     * TODO: use a public Keycloak API once it exposes the mapper directly.
     */
    public static final String KEYCLOAK_MAPPER_HOLDER = "org.keycloak.admin.client.jackson3.Jackson3MapperHolder";
    static final String KEYCLOAK_MAPPER_FIELD = "MAPPER";

    private KeycloakAdminClientJsonMapper() {
    }

    /**
     * @param bridgeJackson2JsonNode whether the Jackson 2 variant of the Keycloak representations is on the classpath,
     *        in which case the Jackson 2 {@code JsonNode} fields of the representations must be bridged, see
     *        {@link Jackson2JsonNodeModule}
     * @return the mapper compatible with the Keycloak admin client; the same instance is returned when no bridge is
     *         required
     */
    public static JsonMapper create(boolean bridgeJackson2JsonNode) {
        JsonMapper keycloakMapper = keycloakMapper();
        if (!bridgeJackson2JsonNode) {
            return keycloakMapper;
        }
        return keycloakMapper.rebuild().addModule(new Jackson2JsonNodeModule()).build();
    }

    private static JsonMapper keycloakMapper() {
        try {
            Class<?> holder = Class.forName(KEYCLOAK_MAPPER_HOLDER, true,
                    KeycloakAdminClientJsonMapper.class.getClassLoader());
            Field mapper = holder.getDeclaredField(KEYCLOAK_MAPPER_FIELD);
            mapper.setAccessible(true);
            return (JsonMapper) mapper.get(null);
        } catch (ReflectiveOperationException | RuntimeException e) {
            throw new IllegalStateException("Failed to obtain the Jackson 3 JsonMapper of the Keycloak admin client from "
                    + KEYCLOAK_MAPPER_HOLDER + "#" + KEYCLOAK_MAPPER_FIELD
                    + ", please make sure the 'org.keycloak:keycloak-admin-client-jackson3' dependency is on the classpath",
                    e);
        }
    }
}
