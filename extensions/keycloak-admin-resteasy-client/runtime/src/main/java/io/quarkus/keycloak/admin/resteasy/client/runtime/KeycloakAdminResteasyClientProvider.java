package io.quarkus.keycloak.admin.resteasy.client.runtime;

import javax.net.ssl.SSLContext;

import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.client.Client;
import jakarta.ws.rs.client.WebTarget;
import jakarta.ws.rs.core.MediaType;

import org.jboss.resteasy.client.jaxrs.ResteasyWebTarget;
import org.jboss.resteasy.client.jaxrs.internal.ResteasyClientBuilderImpl;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.spi.ResteasyClientProvider;

import io.quarkus.keycloak.admin.client.common.runtime.KeycloakAdminClientJsonMapper;
import io.quarkus.resteasy.common.runtime.jackson.QuarkusJacksonSerializer;
import io.quarkus.tls.TlsConfiguration;
import tools.jackson.databind.json.JsonMapper;

public class KeycloakAdminResteasyClientProvider implements ResteasyClientProvider {

    private final TlsConfiguration namedTlsConfig;
    private final boolean globalTrustAll;
    private final boolean bridgeJackson2JsonNode;
    private volatile JsonMapper jsonMapper;

    /**
     * Used by Keycloak to load this provider through the {@link java.util.ServiceLoader} when the {@link Keycloak}
     * class is initialized; the provider configured from the Quarkus configuration replaces it at startup,
     * see {@link KeycloakAdminResteasyClientRecorder#setClientProvider}.
     */
    public KeycloakAdminResteasyClientProvider() {
        this(null, false, false);
    }

    /**
     * @param namedTlsConfig the TLS configuration selected by {@code quarkus.keycloak.admin-client.tls-configuration-name},
     *        may be {@code null}
     * @param globalTrustAll whether the default TLS configuration trusts all certificates, only used when there is
     *        no named TLS configuration
     * @param bridgeJackson2JsonNode see {@link KeycloakAdminClientJsonMapper#create(boolean)}
     */
    public KeycloakAdminResteasyClientProvider(TlsConfiguration namedTlsConfig, boolean globalTrustAll,
            boolean bridgeJackson2JsonNode) {
        this.namedTlsConfig = namedTlsConfig;
        this.globalTrustAll = globalTrustAll;
        this.bridgeJackson2JsonNode = bridgeJackson2JsonNode;
    }

    @Override
    public Client newRestEasyClient(Object customJacksonProvider, SSLContext sslContext, boolean disableTrustManager) {
        // this is what 'org.keycloak.admin.client.jackson3.ResteasyClientClassicProvider3' does
        var builder = new ResteasyClientBuilderImpl();
        builder.connectionPoolSize(10);

        if (namedTlsConfig == null) {
            builder.sslContext(sslContext);
            if (globalTrustAll || disableTrustManager) {
                builder.disableTrustManager();
            }
        } else {
            if (namedTlsConfig.isTrustAll()) {
                builder.disableTrustManager();
            }
            try {
                builder.sslContext(namedTlsConfig.createSSLContext());
            } catch (Exception e) {
                throw new RuntimeException("Failed to create Keycloak Admin client SSLContext", e);
            }
        }

        // this ensures we don't customize managed (shared) ObjectMapper available in the CDI container
        // and that we use QuarkusJacksonSerializer that works in native mode
        builder.register(new AppJsonQuarkusJacksonSerializer(jsonMapper()), 100);

        return builder.build();
    }

    @Override
    public <R> R targetProxy(WebTarget webTarget, Class<R> aClass) {
        return (ResteasyWebTarget.class.cast(webTarget)).proxy(aClass);
    }

    // the mapper configured by the Keycloak admin client for its representations
    private JsonMapper jsonMapper() {
        JsonMapper mapper = jsonMapper;
        if (mapper == null) {
            // the mapper is immutable, a benign race only creates an equivalent instance
            mapper = KeycloakAdminClientJsonMapper.create(bridgeJackson2JsonNode);
            jsonMapper = mapper;
        }
        return mapper;
    }

    // makes media type more specific which ensures that it will be used first
    @Produces(MediaType.APPLICATION_JSON)
    @Consumes(MediaType.APPLICATION_JSON)
    static final class AppJsonQuarkusJacksonSerializer extends QuarkusJacksonSerializer {

        private final JsonMapper jsonMapper;

        private AppJsonQuarkusJacksonSerializer(JsonMapper jsonMapper) {
            this.jsonMapper = jsonMapper;
        }

        @Override
        public JsonMapper locateMapper(Class<?> type, MediaType mediaType) {
            return jsonMapper;
        }

    }
}
