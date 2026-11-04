package io.quarkus.spiffe.client.runtime.internal;

import java.util.function.Supplier;

import io.quarkus.tls.TlsConfiguration;

public record SpiffeTlsConfigurationSupplier(String tlsConfigurationName,
        String spiffeId) implements Supplier<TlsConfiguration> {
    @Override
    public TlsConfiguration get() {
        return new SpiffeTlsConfiguration(tlsConfigurationName, spiffeId, SpiffeTlsConfigurationManager.get());
    }
}
