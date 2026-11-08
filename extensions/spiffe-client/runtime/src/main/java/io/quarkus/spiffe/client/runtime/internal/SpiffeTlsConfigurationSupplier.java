package io.quarkus.spiffe.client.runtime.internal;

import static io.smallrye.common.expression.Expression.Flag.LENIENT_SYNTAX;
import static io.smallrye.common.expression.Expression.Flag.NO_TRIM;

import java.util.Optional;
import java.util.Set;
import java.util.function.Supplier;

import io.quarkus.runtime.configuration.ConfigurationException;
import io.quarkus.tls.TlsConfiguration;
import io.smallrye.common.expression.Expression;
import io.smallrye.config.Config;

public record SpiffeTlsConfigurationSupplier(String tlsConfigurationName,
        String spiffeId) implements Supplier<TlsConfiguration> {
    @Override
    public TlsConfiguration get() {
        return new SpiffeTlsConfiguration(tlsConfigurationName, resolveSpiffeId(), SpiffeTlsConfigurationManager.get());
    }

    private String resolveSpiffeId() {
        if (!spiffeId.contains("${")) {
            return spiffeId;
        }
        final Config config = Config.get();
        return Expression.compile(spiffeId, LENIENT_SYNTAX, NO_TRIM).evaluate((context, builder) -> {
            Optional<String> value = config.getOptionalValue(context.getKey(), String.class);
            if (value.isPresent()) {
                builder.append(value.get());
            } else if (context.hasDefault()) {
                context.expandDefault();
            } else {
                throw new ConfigurationException("Could not expand '" + context.getKey() + "' in the SPIFFE ID '"
                        + spiffeId + "' of the TLS configuration '" + tlsConfigurationName + "'",
                        Set.of(context.getKey()));
            }
        });
    }
}
