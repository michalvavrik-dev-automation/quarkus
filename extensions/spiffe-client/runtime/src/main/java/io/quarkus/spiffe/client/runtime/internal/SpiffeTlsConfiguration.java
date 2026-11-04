package io.quarkus.spiffe.client.runtime.internal;

import java.security.KeyStore;
import java.util.Optional;

import javax.net.ssl.SSLContext;

import io.quarkus.tls.TlsConfiguration;
import io.vertx.core.net.ClientSSLOptions;
import io.vertx.core.net.KeyCertOptions;
import io.vertx.core.net.SSLEngineOptions;
import io.vertx.core.net.ServerSSLOptions;
import io.vertx.core.net.TrustOptions;

record SpiffeTlsConfiguration(String tlsConfigurationName, String spiffeId,
        SpiffeTlsConfigurationManager tlsConfigurationManager) implements TlsConfiguration {

    // TODO: validate reload period is lower than svid ttl
    // TODO: validate reload period correct period during the build time
    // TODO: validate that tls config of this name is not configured by user otherwise fail
    // TODO: validate TLS registry present or fail build
    // TODO: ensure all methods are enforcing spiffe id authorization check
    // TODO: validate spiffe id

    @Override
    public String getName() {
        return tlsConfigurationName;
    }

    @Override
    public Optional<SSLEngineOptions> getSslEngineOptions() {
        // TODO: impl. me!
        return Optional.empty();
    }

    @Override
    public boolean reload() {
        // TODO: impl. me!
        return false;
    }

    @Override
    public boolean usesSni() {
        return false;
    }

    @Override
    public Optional<String> getHostnameVerificationAlgorithm() {
        return Optional.of("NONE");
    }

    @Override
    public boolean isTrustAll() {
        return false;
    }

    @Override
    public SSLContext createSSLContext() {
        // TODO: impl. me!
        return null;
    }

    @Override
    public ClientSSLOptions getClientSSLOptions() {
        // TODO: impl. me!
        return null;
    }

    @Override
    public ServerSSLOptions getServerSSLOptions() {
        // TODO: impl. me!
        return null;
    }

    @Override
    public TrustOptions getTrustStoreOptions() {
        // TODO: impl. me!
        return null;
    }

    @Override
    public KeyStore getTrustStore() {
        throw new UnsupportedOperationException(
                "SPIFFE X.509-SVID TLS configurations do not expose a raw trust store, as it cannot enforce "
                        + "SPIFFE ID authorization; use getTrustStoreOptions() instead.");
    }

    @Override
    public KeyCertOptions getKeyStoreOptions() {
        // TODO: impl. me!
        return null;
    }

    @Override
    public KeyStore getKeyStore() {
        throw new UnsupportedOperationException(
                "SPIFFE X.509-SVID TLS configurations do not expose a raw key store, as consumers of it build their own "
                        + "TLS context that skips SPIFFE ID authorization; use getKeyStoreOptions() instead.");
    }
}
