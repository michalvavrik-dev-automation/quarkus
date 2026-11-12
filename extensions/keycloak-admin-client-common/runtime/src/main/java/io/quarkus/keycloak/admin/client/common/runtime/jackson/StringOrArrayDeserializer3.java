/*
 * Copied from org.keycloak.admin.client.jackson3 of org.keycloak:keycloak-admin-client-jackson3 (keycloak-client 26.0.13,
 * Apache License 2.0), where these classes are package-private. Only the package and the visibility were changed,
 * keep in sync when bumping the Keycloak client.
 */
package io.quarkus.keycloak.admin.client.common.runtime.jackson;

import java.util.ArrayList;

import tools.jackson.core.JsonParser;
import tools.jackson.databind.DeserializationContext;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ValueDeserializer;

public class StringOrArrayDeserializer3 extends ValueDeserializer<Object> {

    @Override
    public Object deserialize(JsonParser p, DeserializationContext ctxt) {
        JsonNode jsonNode = ctxt.readTree(p);
        if (jsonNode.isArray()) {
            ArrayList<String> a = new ArrayList<>(1);
            for (JsonNode child : jsonNode) {
                a.add(child.stringValue());
            }
            return a.toArray(new String[0]);
        } else {
            return new String[] { jsonNode.stringValue() };
        }
    }
}
