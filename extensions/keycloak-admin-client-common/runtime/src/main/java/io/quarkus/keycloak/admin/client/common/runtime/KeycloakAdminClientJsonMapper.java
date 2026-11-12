package io.quarkus.keycloak.admin.client.common.runtime;

import com.fasterxml.jackson.annotation.JsonInclude;

import io.quarkus.keycloak.admin.client.common.runtime.jackson.KeycloakAnnotationIntrospector3;
import tools.jackson.databind.AnnotationIntrospector;
import tools.jackson.databind.DeserializationFeature;
import tools.jackson.databind.json.JsonMapper;

/**
 * Creates the Jackson 3 {@link JsonMapper} used by the Keycloak admin client extensions to (de)serialize
 * the Keycloak representations.
 */
public final class KeycloakAdminClientJsonMapper {

    private KeycloakAdminClientJsonMapper() {
    }

    /**
     * @param bridgeJackson2JsonNode whether the Jackson 2 variant of the Keycloak representations is on the classpath,
     *        in which case the Jackson 2 {@code JsonNode} fields of the representations must be bridged, see
     *        {@link Jackson2JsonNodeModule}
     * @return the mapper configured like the one of the Keycloak admin client for Jackson 3,
     *         see {@code org.keycloak.admin.client.jackson3.Jackson3MapperHolder}
     */
    public static JsonMapper create(boolean bridgeJackson2JsonNode) {
        // Same like JSONSerialization class. Makes it possible to use admin-client against older versions of Keycloak server where the properties on representations might be different
        // The client must work with the newer versions of Keycloak server, which might contain the JSON fields not yet known by the client. So unknown fields will be ignored.
        JsonMapper defaultMapper = JsonMapper.builder()
                .changeDefaultPropertyInclusion(
                        v -> JsonInclude.Value.construct(JsonInclude.Include.NON_NULL, JsonInclude.Include.NON_NULL))
                .disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES)
                .build();
        // the Keycloak annotations like @StringOrArray are only applied through the Keycloak annotation introspector
        JsonMapper.Builder builder = defaultMapper.rebuild()
                .annotationIntrospector(AnnotationIntrospector.pair(
                        new KeycloakAnnotationIntrospector3(),
                        defaultMapper.serializationConfig().getAnnotationIntrospector()));
        if (bridgeJackson2JsonNode) {
            builder.addModule(new Jackson2JsonNodeModule());
        }
        return builder.build();
    }
}
