/*
 * Copied from org.keycloak.admin.client.jackson3 of org.keycloak:keycloak-admin-client-jackson3 (keycloak-client 26.0.13,
 * Apache License 2.0), where these classes are package-private. Only the package and the visibility were changed,
 * keep in sync when bumping the Keycloak client.
 */
package io.quarkus.keycloak.admin.client.common.runtime.jackson;

import tools.jackson.core.JsonGenerator;
import tools.jackson.databind.SerializationContext;
import tools.jackson.databind.ValueSerializer;

public class StringOrArraySerializer3 extends ValueSerializer<Object> {
    @Override
    public void serialize(Object o, JsonGenerator gen, SerializationContext ctxt) {
        String[] array = (String[]) o;
        if (array == null) {
            gen.writeNull();
        } else if (array.length == 1) {
            gen.writeString(array[0]);
        } else {
            gen.writeStartArray();
            for (String s : array) {
                gen.writeString(s);
            }
            gen.writeEndArray();
        }
    }
}
