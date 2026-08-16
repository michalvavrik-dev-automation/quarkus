package io.quarkus.oidc.runtime;

import io.quarkus.oidc.OidcTenantConfig;

/**
 * OIDC routes that tenants can use. Each route requires a dedicated HTTP handler;
 * remove routes no tenant needs to avoid unnecessary overhead.
 */
public enum OidcRoute {
    /**
     * Allows tenants to use back-channel logout by accepting logout notifications from the OIDC provider.
     *
     * @see OidcTenantConfig.Backchannel
     */
    BACKCHANNEL_LOGOUT,
    /**
     * Allows tenants to publish protected resource metadata as defined by
     * <a href="https://datatracker.ietf.org/doc/rfc9728/">RFC 9728</a>.
     *
     * @see OidcTenantConfig.ResourceMetadata
     */
    RESOURCE_METADATA
}
