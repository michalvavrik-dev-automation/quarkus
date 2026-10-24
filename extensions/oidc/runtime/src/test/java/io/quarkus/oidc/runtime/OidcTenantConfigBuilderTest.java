package io.quarkus.oidc.runtime;

import static io.quarkus.oidc.runtime.OidcTenantConfig.Authentication.ResponseMode.FORM_POST;
import static io.quarkus.oidc.runtime.OidcTenantConfig.Authentication.ResponseMode.QUERY;
import static io.quarkus.oidc.runtime.OidcTenantConfig.Roles.Source.accesstoken;
import static io.quarkus.oidc.runtime.OidcTenantConfig.Roles.Source.idtoken;
import static io.quarkus.oidc.runtime.OidcTenantConfig.Roles.Source.userinfo;
import static io.quarkus.oidc.runtime.OidcTenantConfig.SignatureAlgorithm.PS384;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.Modifier;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.BiConsumer;

import org.junit.jupiter.api.Test;

import io.quarkus.oidc.OidcTenantConfig;
import io.quarkus.oidc.OidcTenantConfigBuilder;
import io.quarkus.oidc.OidcTenantConfigBuilder.CertificateChainBuilder;
import io.quarkus.oidc.OidcTenantConfigBuilder.CodeGrantBuilder;
import io.quarkus.oidc.OidcTenantConfigBuilder.IntrospectionCredentialsBuilder;
import io.quarkus.oidc.OidcTenantConfigBuilder.JwksBuilder;
import io.quarkus.oidc.OidcTenantConfigBuilder.RolesBuilder;
import io.quarkus.oidc.OidcTenantConfigBuilder.TokenStateManagerBuilder;
import io.quarkus.oidc.common.runtime.OidcConstants;
import io.quarkus.oidc.common.runtime.config.OidcClientCommonConfig.Credentials.Attestation.AttestationSignatureAlgorithm;
import io.quarkus.oidc.common.runtime.config.OidcClientCommonConfig.Credentials.Jwt.Source;
import io.quarkus.oidc.common.runtime.config.OidcClientCommonConfig.Credentials.Secret.Method;
import io.quarkus.oidc.common.runtime.config.OidcClientCommonConfigBuilder.CredentialsBuilder;
import io.quarkus.oidc.common.runtime.config.OidcClientCommonConfigBuilder.JwtBuilder;
import io.quarkus.oidc.common.runtime.config.OidcClientCommonConfigBuilder.SecretBuilder;
import io.quarkus.oidc.runtime.OidcTenantConfig.ApplicationType;
import io.quarkus.oidc.runtime.OidcTenantConfig.Authentication.CacheControl;
import io.quarkus.oidc.runtime.OidcTenantConfig.Authentication.CookieSameSite;
import io.quarkus.oidc.runtime.OidcTenantConfig.Logout.ClearSiteData;
import io.quarkus.oidc.runtime.OidcTenantConfig.Logout.LogoutMode;
import io.quarkus.oidc.runtime.OidcTenantConfig.Provider;
import io.quarkus.oidc.runtime.OidcTenantConfig.SignatureAlgorithm;
import io.quarkus.oidc.runtime.OidcTenantConfig.Token.DecryptionAlgorithm;
import io.quarkus.oidc.runtime.OidcTenantConfig.TokenStateManager.EncryptionAlgorithm;
import io.quarkus.oidc.runtime.OidcTenantConfig.TokenStateManager.Strategy;
import io.quarkus.oidc.runtime.builders.AuthenticationConfigBuilder;
import io.quarkus.oidc.runtime.builders.LogoutConfigBuilder;
import io.quarkus.oidc.runtime.builders.LogoutConfigBuilder.BackchannelBuilder;
import io.quarkus.oidc.runtime.builders.TokenConfigBuilder;

public class OidcTenantConfigBuilderTest {

    private int comparedProperties;

    @Test
    public void testDefaultValues() {
        var config = OidcTenantConfig.builder().tenantId("default-test").build();

        // OidcTenantConfig methods
        assertTrue(config.tenantId().isPresent());
        assertTrue(config.tenantEnabled());
        assertTrue(config.applicationType().isEmpty());
        assertTrue(config.authorizationPath().isEmpty());
        assertTrue(config.userInfoPath().isEmpty());
        assertTrue(config.introspectionPath().isEmpty());
        assertTrue(config.jwksPath().isEmpty());
        assertTrue(config.endSessionPath().isEmpty());
        assertTrue(config.tenantPaths().isEmpty());
        assertTrue(config.publicKey().isEmpty());
        assertTrue(config.allowTokenIntrospectionCache());
        assertTrue(config.allowUserInfoCache());
        assertTrue(config.cacheUserInfoInIdtoken().isEmpty());
        assertTrue(config.provider().isEmpty());
        assertEquals(Duration.ofMinutes(2), config.dpop().proofAge());

        var introspectionCredentials = config.introspectionCredentials();
        assertNotNull(introspectionCredentials);
        assertTrue(introspectionCredentials.name().isEmpty());
        assertTrue(introspectionCredentials.secret().isEmpty());
        assertTrue(introspectionCredentials.includeClientId());

        var roles = config.roles();
        assertNotNull(roles);
        assertTrue(roles.roleClaimPath().isEmpty());
        assertTrue(roles.roleClaimSeparator().isEmpty());
        assertTrue(roles.source().isEmpty());

        var token = config.token();
        assertNotNull(token);
        assertTrue(token.issuer().isEmpty());
        assertTrue(token.audience().isEmpty());
        assertFalse(token.subjectRequired());
        assertTrue(token.requiredClaims().isEmpty());
        assertTrue(token.tokenType().isEmpty());
        assertTrue(token.lifespanGrace().isEmpty());
        assertTrue(token.age().isEmpty());
        assertTrue(token.issuedAtRequired());
        assertTrue(token.principalClaim().isEmpty());
        assertFalse(token.refreshExpired());
        assertTrue(token.refreshTokenTimeSkew().isEmpty());
        assertEquals(10, token.forcedJwkRefreshInterval().toMinutes());
        assertTrue(token.header().isEmpty());
        assertEquals(OidcConstants.BEARER_SCHEME, token.authorizationScheme());
        assertTrue(token.signatureAlgorithm().isEmpty());
        assertTrue(token.decryptionKeyLocation().isEmpty());
        assertTrue(token.decryptionAlgorithm().isEmpty());
        assertTrue(token.allowJwtIntrospection());
        assertFalse(token.requireJwtIntrospectionOnly());
        assertTrue(token.allowOpaqueTokenIntrospection());
        assertTrue(token.customizerName().isEmpty());
        assertTrue(token.verifyAccessTokenWithUserInfo().isEmpty());
        assertEquals(Duration.ZERO, token.refreshTokenCacheTimeToLive());

        var logout = config.logout();
        assertNotNull(logout);
        assertTrue(logout.path().isEmpty());
        assertTrue(logout.postLogoutPath().isEmpty());
        assertEquals(OidcConstants.POST_LOGOUT_REDIRECT_URI, logout.postLogoutUriParam());
        assertTrue(logout.extraParams().isEmpty());

        var backchannel = logout.backchannel();
        assertNotNull(backchannel);
        assertTrue(backchannel.path().isEmpty());
        assertEquals(10, backchannel.tokenCacheSize());
        assertEquals(10, backchannel.tokenCacheTimeToLive().toMinutes());
        assertTrue(backchannel.cleanUpTimerInterval().isEmpty());
        assertEquals("sub", backchannel.logoutTokenKey());

        var frontchannel = logout.frontchannel();
        assertNotNull(frontchannel);
        assertTrue(frontchannel.path().isEmpty());

        var certificateChain = config.certificateChain();
        assertNotNull(certificateChain);
        assertTrue(certificateChain.leafCertificateName().isEmpty());
        assertTrue(certificateChain.trustStoreFile().isEmpty());
        assertTrue(certificateChain.trustStorePassword().isEmpty());
        assertTrue(certificateChain.trustStoreCertAlias().isEmpty());
        assertTrue(certificateChain.trustStoreFileType().isEmpty());

        var authentication = config.authentication();
        assertNotNull(authentication);
        assertTrue(authentication.responseMode().isEmpty());
        assertTrue(authentication.redirectPath().isEmpty());
        assertFalse(authentication.restorePathAfterRedirect());
        assertTrue(authentication.removeRedirectParameters());
        assertTrue(authentication.errorPath().isEmpty());
        assertTrue(authentication.sessionExpiredPath().isEmpty());
        assertFalse(authentication.verifyAccessToken());
        assertTrue(authentication.forceRedirectHttpsScheme().isEmpty());
        assertTrue(authentication.scopes().isEmpty());
        assertTrue(authentication.scopeSeparator().isEmpty());
        assertFalse(authentication.nonceRequired());
        assertTrue(authentication.addOpenidScope().isEmpty());
        assertTrue(authentication.extraParams().isEmpty());
        assertTrue(authentication.forwardParams().isEmpty());
        assertFalse(authentication.cookieForceSecure());
        assertTrue(authentication.cookieSuffix().isEmpty());
        assertEquals("/", authentication.cookiePath());
        assertTrue(authentication.cookiePathHeader().isEmpty());
        assertTrue(authentication.cookieDomain().isEmpty());
        assertEquals(CookieSameSite.LAX, authentication.cookieSameSite());
        assertTrue(authentication.allowMultipleCodeFlows());
        assertFalse(authentication.failOnMissingStateParam());
        assertTrue(authentication.userInfoRequired().isEmpty());
        assertTrue(authentication.sessionAgeExtension().isEmpty());
        assertEquals(5, authentication.stateCookieAge().toMinutes());
        assertTrue(authentication.javaScriptAutoRedirect());
        assertTrue(authentication.idTokenRequired().isEmpty());
        assertTrue(authentication.internalIdTokenLifespan().isEmpty());
        assertTrue(authentication.pkceRequired().isEmpty());
        assertTrue(authentication.stateSecret().isEmpty());
        assertTrue(authentication.par().enabled().isEmpty());
        assertTrue(authentication.par().path().isEmpty());

        var codeGrant = config.codeGrant();
        assertNotNull(codeGrant);
        assertTrue(codeGrant.extraParams().isEmpty());
        assertTrue(codeGrant.headers().isEmpty());

        var tokenStateManager = config.tokenStateManager();
        assertNotNull(tokenStateManager);
        assertEquals(Strategy.KEEP_ALL_TOKENS, tokenStateManager.strategy());
        assertFalse(tokenStateManager.splitTokens());
        assertTrue(tokenStateManager.encryptionRequired());
        assertTrue(tokenStateManager.encryptionSecret().isEmpty());
        assertEquals(EncryptionAlgorithm.A256GCMKW, tokenStateManager.encryptionAlgorithm());

        var jwks = config.jwks();
        assertNotNull(jwks);
        assertTrue(jwks.resolveEarly());
        assertEquals(10, jwks.cacheSize());
        assertEquals(10, jwks.cacheTimeToLive().toMinutes());
        assertTrue(jwks.cleanUpTimerInterval().isEmpty());
        assertFalse(jwks.tryAll());

        var clientIdMetadata = config.clientIdMetadata();
        assertNotNull(clientIdMetadata);
        assertTrue(clientIdMetadata.forceHttpsScheme());

        // OidcClientCommonConfig methods
        assertTrue(config.tokenPath().isEmpty());
        assertTrue(config.revokePath().isEmpty());
        assertTrue(config.clientId().isEmpty());
        assertTrue(config.clientName().isEmpty());
        var credentials = config.credentials();
        assertNotNull(credentials);
        assertTrue(credentials.secret().isEmpty());
        var clientSecret = credentials.clientSecret();
        assertNotNull(clientSecret);
        assertTrue(clientSecret.value().isEmpty());
        assertTrue(clientSecret.method().isEmpty());
        var provider = clientSecret.provider();
        assertNotNull(provider);
        assertTrue(provider.key().isEmpty());
        assertTrue(provider.keyringName().isEmpty());
        assertTrue(provider.name().isEmpty());
        var jwt = credentials.jwt();
        assertNotNull(jwt);
        assertEquals(Source.CLIENT, jwt.source());
        assertTrue(jwt.secret().isEmpty());
        provider = jwt.secretProvider();
        assertNotNull(provider);
        assertTrue(provider.key().isEmpty());
        assertTrue(provider.keyringName().isEmpty());
        assertTrue(provider.name().isEmpty());
        assertTrue(jwt.key().isEmpty());
        assertTrue(jwt.keyFile().isEmpty());
        assertTrue(jwt.keyStoreFile().isEmpty());
        assertTrue(jwt.keyStorePassword().isEmpty());
        assertTrue(jwt.keyId().isEmpty());
        assertTrue(jwt.keyPassword().isEmpty());
        assertTrue(jwt.audience().isEmpty());
        assertTrue(jwt.tokenKeyId().isEmpty());
        assertTrue(jwt.issuer().isEmpty());
        assertTrue(jwt.subject().isEmpty());
        assertTrue(jwt.claims().isEmpty());
        assertTrue(jwt.signatureAlgorithm().isEmpty());
        assertEquals(10, jwt.lifespan());
        assertFalse(jwt.assertion());
        assertTrue(jwt.tokenPath().isEmpty());

        // OidcCommonConfig methods
        assertTrue(config.authServerUrl().isEmpty());
        assertTrue(config.discoveryEnabled().isEmpty());
        assertTrue(config.registrationPath().isEmpty());
        assertTrue(config.connectionDelay().isEmpty());
        assertEquals(3, config.connectionRetryCount());
        assertEquals(10, config.connectionTimeout().getSeconds());
        assertFalse(config.useBlockingDnsLookup());
        assertTrue(config.maxPoolSize().isEmpty());
        assertTrue(config.followRedirects());
        assertNotNull(config.proxy());
        assertNotNull(config.tls());
        assertTrue(config.tls().tlsConfigurationName().isEmpty());
    }

    @Test
    public void testSetEveryProperty() {
        var config = OidcTenantConfig.builder()
                // OidcTenantConfig methods
                .tenantId("set-every-property-test")
                .disableTenant()
                .applicationType(ApplicationType.HYBRID)
                .authorizationPath("authorization-path-test")
                .userInfoPath("user-info-path-test")
                .introspectionPath("introspection-path-test")
                .jwksPath("jwks-path-test")
                .endSessionPath("end-session-path-test")
                .tenantPaths("tenant-path-test")
                .publicKey("public-key-test")
                .allowTokenIntrospectionCache()
                .allowUserInfoCache()
                .cacheUserInfoInIdtoken()
                .provider(Provider.FACEBOOK)
                .introspectionCredentials().name("i-name").secret("i-secret").includeClientId(false).end()
                .roles().roleClaimSeparator("@#$").roleClaimPath("separator-23").source(idtoken).end()
                .token()
                .refreshTokenCacheTimeToLive(Duration.ofSeconds(30))
                .verifyAccessTokenWithUserInfo()
                .customizerName("customizer-name-8")
                .allowOpaqueTokenIntrospection(false)
                .requireJwtIntrospectionOnly()
                .allowJwtIntrospection(false)
                .decryptionKeyLocation("decryption-key-location-test")
                .decryptionAlgorithm(DecryptionAlgorithm.RSA_OAEP_256)
                .signatureAlgorithm(PS384)
                .authorizationScheme("bearer-1234")
                .header("doloris")
                .forcedJwkRefreshInterval(Duration.ofMinutes(100))
                .refreshTokenTimeSkew(Duration.ofMinutes(99))
                .refreshExpired()
                .principalClaim("potter")
                .issuedAtRequired(false)
                .age(Duration.ofMinutes(68))
                .lifespanGrace(99)
                .tokenType("McGonagall")
                .requiredClaims("req-claim-name", "req-claim-val")
                .requiredClaims("req-array-claim-name", Set.of("item-1", "item-2"))
                .subjectRequired()
                .audience("professor hagrid")
                .issuer("issuer-3")
                .end()
                .logout()
                .path("logout-path-1")
                .extraParam("extra-param-key-8", "extra-param-val-8")
                .frontchannelPath("front-channel-path-7")
                .postLogoutPath("post-logout-path-4")
                .postLogoutUriParam("post-logout-uri-param-1")
                .backchannel()
                .path("backchannel-path-6")
                .tokenCacheTimeToLive(Duration.ofMinutes(3))
                .cleanUpTimerInterval(Duration.ofMinutes(5))
                .logoutTokenKey("logout-token-key-6")
                .tokenCacheSize(9)
                .endLogout()
                .certificateChain()
                .trustStoreFile(Path.of("here"))
                .trustStoreCertAlias("trust-store-cert-alias-test-30")
                .trustStorePassword("trust-store-password-test-64")
                .trustStoreFileType("trust-store-file-type-test-636")
                .leafCertificateName("leaf-certificate-name-test-875")
                .end()
                .codeGrant()
                .extraParam("2", "two")
                .extraParam("4", "three!")
                .header("1", "123")
                .header("3", "321")
                .header("5", "222")
                .end()
                .tokenStateManager()
                .strategy(Strategy.ID_REFRESH_TOKENS)
                .splitTokens()
                .encryptionRequired(false)
                .encryptionSecret("encryption-secret-test-999")
                .encryptionAlgorithm(EncryptionAlgorithm.DIR)
                .end()
                .jwks()
                .tryAll()
                .cleanUpTimerInterval(Duration.ofMinutes(1))
                .cacheTimeToLive(Duration.ofMinutes(2))
                .cacheSize(55)
                .resolveEarly(false)
                .end()
                .clientIdMetadata().forceHttpsScheme(false).end()
                // OidcClientCommonConfig methods
                .tokenPath("token-path-yep")
                .revokePath("revoke-path-yep")
                .clientId("client-id-yep")
                .clientName("client-name-yep")
                .credentials()
                .secret("secret-yep")
                .clientSecret()
                .method(Method.QUERY)
                .value("value-yep")
                .provider("key-yep", "name-yep", "keyring-name-yep")
                .end()
                .jwt()
                .source(Source.BEARER)
                .tokenPath(Path.of("my-super-bearer-path"))
                .secretProvider()
                .keyringName("jwt-keyring-name-yep")
                .key("jwt-key-yep")
                .name("jwt-name-yep")
                .end()
                .secret("jwt-secret-yep")
                .key("jwt-key-yep")
                .keyFile("jwt-key-file-yep")
                .keyStoreFile("jwt-key-store-file-yep")
                .keyStorePassword("jwt-key-store-password-yep")
                .keyId("jwt-key-id-yep")
                .keyPassword("jwt-key-pwd-yep")
                .audience("jwt-audience-yep")
                .tokenKeyId("jwt-token-key-id-yep")
                .issuer("jwt-issuer")
                .subject("jwt-subject")
                .claim("claim-one-name", "claim-one-value")
                .claims(Map.of("claim-two-name", "claim-two-value"))
                .signatureAlgorithm("ES512")
                .lifespan(852)
                .assertion(true)
                .endCredentials()
                .authentication()
                .responseMode(QUERY)
                .redirectPath("/redirect-path-auth-yep")
                .restorePathAfterRedirect()
                .removeRedirectParameters(false)
                .errorPath("/error-path-auth-yep")
                .sessionExpiredPath("/session-expired-path-auth-yep")
                .verifyAccessToken()
                .forceRedirectHttpsScheme()
                .scopes(List.of("scope-one", "scope-two", "scope-three"))
                .scopeSeparator("scope-separator-654456")
                .nonceRequired()
                .addOpenidScope(false)
                .extraParam("ex-auth-param-6-key", "ex-auth-param-6-val")
                .extraParam("ex-auth-param-7-key", "ex-auth-param-7-val")
                .forwardParams("forward-param-6-key", "forward-param-6-val")
                .forwardParams("forward-param-7-key", "forward-param-7-val")
                .cookieForceSecure()
                .cookieSuffix("cookie-suffix-auth-whatever")
                .cookiePath("/cookie-path-auth-whatever")
                .cookiePathHeader("cookie-path-header-auth-whatever")
                .cookieDomain("cookie-domain-auth-whatever")
                .cookieSameSite(CookieSameSite.STRICT)
                .allowMultipleCodeFlows(false)
                .failOnMissingStateParam()
                .userInfoRequired()
                .sessionAgeExtension(Duration.ofMinutes(77))
                .stateCookieAge(Duration.ofMinutes(88))
                .javaScriptAutoRedirect(false)
                .idTokenRequired(false)
                .internalIdTokenLifespan(Duration.ofMinutes(357))
                .pkceRequired()
                .stateSecret("state-secret-auth-whatever")
                .par("/as/par")
                .rar("openid_credential", Map.of("credentials", "mine"), Map.of("locations", List.of("something")))
                .end()
                // OidcCommonConfig methods
                .authServerUrl("we")
                .discoveryEnabled(false)
                .registrationPath("don't")
                .connectionDelay(Duration.ofSeconds(656))
                .connectionRetryCount(565)
                .connectionTimeout(Duration.ofSeconds(673))
                .useBlockingDnsLookup(true)
                .maxPoolSize(376)
                .followRedirects(false)
                .tlsConfigurationName("Teacher!")
                .proxyConfigurationName("Kreacher!")
                .dpop(Duration.ofSeconds(20))
                .build();

        // OidcTenantConfig methods
        assertEquals("set-every-property-test", config.tenantId().orElse(null));
        assertFalse(config.tenantEnabled());
        assertEquals(ApplicationType.HYBRID, config.applicationType().orElse(null));
        assertEquals("authorization-path-test", config.authorizationPath().orElse(null));
        assertEquals("user-info-path-test", config.userInfoPath().orElse(null));
        assertEquals("introspection-path-test", config.introspectionPath().orElse(null));
        assertEquals("jwks-path-test", config.jwksPath().orElse(null));
        assertEquals("end-session-path-test", config.endSessionPath().orElse(null));
        assertEquals(1, config.tenantPaths().orElseThrow().size());
        assertEquals("tenant-path-test", config.tenantPaths().orElseThrow().get(0));
        assertEquals("public-key-test", config.publicKey().orElse(null));
        assertTrue(config.allowTokenIntrospectionCache());
        assertTrue(config.allowUserInfoCache());
        assertTrue(config.cacheUserInfoInIdtoken().orElseThrow());
        assertEquals(Provider.FACEBOOK, config.provider().orElse(null));
        assertEquals(Duration.ofSeconds(20), config.dpop().proofAge());

        var introspectionCredentials = config.introspectionCredentials();
        assertNotNull(introspectionCredentials);
        assertEquals("i-name", introspectionCredentials.name().get());
        assertEquals("i-secret", introspectionCredentials.secret().get());
        assertFalse(introspectionCredentials.includeClientId());

        var roles = config.roles();
        assertNotNull(roles);
        var roleClaimPaths = roles.roleClaimPath().orElse(null);
        assertNotNull(roleClaimPaths);
        assertEquals(1, roleClaimPaths.size());
        assertTrue(roleClaimPaths.contains("separator-23"));
        assertEquals("@#$", roles.roleClaimSeparator().orElse(null));
        assertEquals(idtoken, roles.source().orElse(null));

        var token = config.token();
        assertNotNull(token);
        assertTrue(token.issuer().isPresent());
        assertEquals("issuer-3", token.issuer().get());
        assertTrue(token.audience().isPresent());
        assertEquals(1, token.audience().get().size());
        assertTrue(token.audience().get().contains("professor hagrid"));
        assertTrue(token.subjectRequired());
        assertEquals(2, token.requiredClaims().size());
        assertEquals("req-claim-val", token.requiredClaims().get("req-claim-name").iterator().next());
        assertEquals(Set.of("item-1", "item-2"), token.requiredClaims().get("req-array-claim-name"));
        assertEquals("McGonagall", token.tokenType().get());
        assertEquals(99, token.lifespanGrace().getAsInt());
        assertEquals(68, token.age().get().toMinutes());
        assertFalse(token.issuedAtRequired());
        assertEquals("potter", token.principalClaim().orElse(null));
        assertTrue(token.refreshExpired());
        assertEquals(99, token.refreshTokenTimeSkew().get().toMinutes());
        assertEquals(100, token.forcedJwkRefreshInterval().toMinutes());
        assertEquals("doloris", token.header().orElse(null));
        assertEquals("bearer-1234", token.authorizationScheme());
        assertEquals(PS384, token.signatureAlgorithm().orElse(null));
        assertEquals("decryption-key-location-test", token.decryptionKeyLocation().orElse(null));
        assertEquals(DecryptionAlgorithm.RSA_OAEP_256, token.decryptionAlgorithm().orElse(null));
        assertFalse(token.allowJwtIntrospection());
        assertTrue(token.requireJwtIntrospectionOnly());
        assertFalse(token.allowOpaqueTokenIntrospection());
        assertEquals("customizer-name-8", token.customizerName().orElse(null));
        assertTrue(token.verifyAccessTokenWithUserInfo().orElseThrow());
        assertEquals(Duration.ofSeconds(30), token.refreshTokenCacheTimeToLive());

        var logout = config.logout();
        assertNotNull(logout);
        assertEquals("logout-path-1", logout.path().orElse(null));
        assertEquals("post-logout-path-4", logout.postLogoutPath().orElse(null));
        assertEquals("post-logout-uri-param-1", logout.postLogoutUriParam());
        assertEquals(1, logout.extraParams().size());
        assertEquals("extra-param-val-8", logout.extraParams().get("extra-param-key-8"));

        var backchannel = logout.backchannel();
        assertNotNull(backchannel);
        assertEquals("backchannel-path-6", backchannel.path().orElse(null));
        assertEquals(9, backchannel.tokenCacheSize());
        assertEquals(3, backchannel.tokenCacheTimeToLive().toMinutes());
        assertEquals(5, backchannel.cleanUpTimerInterval().orElseThrow().toMinutes());
        assertEquals("logout-token-key-6", backchannel.logoutTokenKey());

        var frontchannel = logout.frontchannel();
        assertNotNull(frontchannel);
        assertEquals("front-channel-path-7", frontchannel.path().orElse(null));

        var certificateChain = config.certificateChain();
        assertNotNull(certificateChain);
        assertTrue(certificateChain.trustStoreFile().toString().contains("here"));
        assertEquals("trust-store-cert-alias-test-30", certificateChain.trustStoreCertAlias().orElse(null));
        assertEquals("trust-store-password-test-64", certificateChain.trustStorePassword().orElse(null));
        assertEquals("trust-store-file-type-test-636", certificateChain.trustStoreFileType().orElse(null));
        assertEquals("leaf-certificate-name-test-875", certificateChain.leafCertificateName().orElse(null));

        var authentication = config.authentication();
        assertNotNull(authentication);
        var forwardParams = authentication.forwardParams().orElseThrow();
        assertEquals(4, forwardParams.size());
        assertTrue(forwardParams.contains("forward-param-6-key"));
        assertTrue(forwardParams.contains("forward-param-7-key"));
        assertTrue(forwardParams.contains("forward-param-6-val"));
        assertTrue(forwardParams.contains("forward-param-7-val"));
        var extraParams = authentication.extraParams();
        assertEquals(2, extraParams.size());
        assertEquals("ex-auth-param-6-val", extraParams.get("ex-auth-param-6-key"));
        assertEquals("ex-auth-param-7-val", extraParams.get("ex-auth-param-7-key"));
        var scopes = authentication.scopes().orElseThrow();
        assertEquals(3, scopes.size());
        assertTrue(scopes.contains("scope-one"));
        assertTrue(scopes.contains("scope-two"));
        assertTrue(scopes.contains("scope-three"));
        assertEquals("scope-separator-654456", authentication.scopeSeparator().orElseThrow());
        assertEquals(QUERY, authentication.responseMode().orElseThrow());
        assertEquals("/session-expired-path-auth-yep", authentication.sessionExpiredPath().orElseThrow());
        assertEquals("/error-path-auth-yep", authentication.errorPath().orElseThrow());
        assertEquals("/redirect-path-auth-yep", authentication.redirectPath().orElseThrow());
        assertFalse(authentication.removeRedirectParameters());
        assertTrue(authentication.restorePathAfterRedirect());
        assertTrue(authentication.verifyAccessToken());
        assertTrue(authentication.forceRedirectHttpsScheme().orElseThrow());
        assertTrue(authentication.nonceRequired());
        assertFalse(authentication.addOpenidScope().orElseThrow());
        assertTrue(authentication.cookieForceSecure());
        assertEquals("cookie-suffix-auth-whatever", authentication.cookieSuffix().orElse(null));
        assertEquals("/cookie-path-auth-whatever", authentication.cookiePath());
        assertEquals("cookie-path-header-auth-whatever", authentication.cookiePathHeader().orElseThrow());
        assertEquals("cookie-domain-auth-whatever", authentication.cookieDomain().orElseThrow());
        assertEquals(CookieSameSite.STRICT, authentication.cookieSameSite());
        assertFalse(authentication.allowMultipleCodeFlows());
        assertTrue(authentication.failOnMissingStateParam());
        assertTrue(authentication.userInfoRequired().orElseThrow());
        assertEquals(77, authentication.sessionAgeExtension().get().toMinutes());
        assertEquals(88, authentication.stateCookieAge().toMinutes());
        assertFalse(authentication.javaScriptAutoRedirect());
        assertFalse(authentication.idTokenRequired().orElseThrow());
        assertEquals(357, authentication.internalIdTokenLifespan().orElseThrow().toMinutes());
        assertTrue(authentication.pkceRequired().orElseThrow());
        assertEquals("state-secret-auth-whatever", authentication.stateSecret().orElse(null));
        var par = authentication.par();
        assertTrue(par.enabled().orElse(false));
        assertEquals("/as/par", par.path().orElse(null));
        var rar = authentication.rar().orElse(null);
        assertNotNull(rar);
        assertEquals("openid_credential", rar.type());
        assertNotNull(rar.array());
        assertEquals(1, rar.array().size());
        assertEquals(List.of("something"), rar.array().get("locations"));
        assertNotNull(rar.simple());
        assertEquals(1, rar.simple().size());
        assertEquals("mine", rar.simple().get("credentials"));

        var codeGrant = config.codeGrant();
        assertNotNull(codeGrant);
        assertEquals(2, codeGrant.extraParams().size());
        assertEquals("two", codeGrant.extraParams().get("2"));
        assertEquals("three!", codeGrant.extraParams().get("4"));
        assertEquals(3, codeGrant.headers().size());
        assertEquals("123", codeGrant.headers().get("1"));
        assertEquals("321", codeGrant.headers().get("3"));
        assertEquals("222", codeGrant.headers().get("5"));

        var tokenStateManager = config.tokenStateManager();
        assertNotNull(tokenStateManager);
        assertEquals(Strategy.ID_REFRESH_TOKENS, tokenStateManager.strategy());
        assertTrue(tokenStateManager.splitTokens());
        assertFalse(tokenStateManager.encryptionRequired());
        assertEquals("encryption-secret-test-999", tokenStateManager.encryptionSecret().orElse(null));
        assertEquals(EncryptionAlgorithm.DIR, tokenStateManager.encryptionAlgorithm());

        var jwks = config.jwks();
        assertNotNull(jwks);
        assertFalse(jwks.resolveEarly());
        assertEquals(55, jwks.cacheSize());
        assertEquals(2, jwks.cacheTimeToLive().toMinutes());
        assertEquals(1, jwks.cleanUpTimerInterval().orElseThrow().toMinutes());
        assertTrue(jwks.tryAll());

        var clientIdMetadata = config.clientIdMetadata();
        assertNotNull(clientIdMetadata);
        assertFalse(clientIdMetadata.forceHttpsScheme());

        // OidcClientCommonConfig methods
        assertEquals("token-path-yep", config.tokenPath().orElse(null));
        assertEquals("revoke-path-yep", config.revokePath().orElse(null));
        assertEquals("client-id-yep", config.clientId().orElse(null));
        assertEquals("client-name-yep", config.clientName().orElse(null));
        var credentials = config.credentials();
        assertNotNull(credentials);
        assertEquals("secret-yep", credentials.secret().orElse(null));
        var clientSecret = credentials.clientSecret();
        assertNotNull(clientSecret);
        assertEquals(Method.QUERY, clientSecret.method().orElse(null));
        assertEquals("value-yep", clientSecret.value().orElse(null));
        var provider = clientSecret.provider();
        assertNotNull(provider);
        assertEquals("key-yep", provider.key().orElse(null));
        assertEquals("name-yep", provider.name().orElse(null));
        assertEquals("keyring-name-yep", provider.keyringName().orElse(null));
        var jwt = credentials.jwt();
        assertNotNull(jwt);
        assertEquals(Source.BEARER, jwt.source());
        assertEquals("jwt-secret-yep", jwt.secret().orElse(null));
        provider = jwt.secretProvider();
        assertNotNull(provider);
        assertEquals("jwt-keyring-name-yep", provider.keyringName().orElse(null));
        assertEquals("jwt-name-yep", provider.name().orElse(null));
        assertEquals("jwt-key-yep", provider.key().orElse(null));
        assertEquals("jwt-key-yep", jwt.key().orElse(null));
        assertEquals("jwt-key-file-yep", jwt.keyFile().orElse(null));
        assertEquals("jwt-key-store-file-yep", jwt.keyStoreFile().orElse(null));
        assertEquals("jwt-key-store-password-yep", jwt.keyStorePassword().orElse(null));
        assertEquals("jwt-key-id-yep", jwt.keyId().orElse(null));
        assertEquals("jwt-key-pwd-yep", jwt.keyPassword().orElse(null));
        assertEquals("jwt-audience-yep", jwt.audience().orElse(null));
        assertEquals("jwt-token-key-id-yep", jwt.tokenKeyId().orElse(null));
        assertEquals("jwt-issuer", jwt.issuer().orElse(null));
        assertEquals("jwt-subject", jwt.subject().orElse(null));
        assertEquals("my-super-bearer-path", jwt.tokenPath().orElseThrow().toString());
        var claims = jwt.claims();
        assertNotNull(claims);
        assertEquals(2, claims.size());
        assertTrue(claims.containsKey("claim-one-name"));
        assertEquals("claim-one-value", claims.get("claim-one-name"));
        assertTrue(claims.containsKey("claim-two-name"));
        assertEquals("claim-two-value", claims.get("claim-two-name"));
        assertEquals("ES512", jwt.signatureAlgorithm().orElse(null));
        assertEquals(852, jwt.lifespan());
        assertTrue(jwt.assertion());

        // OidcCommonConfig methods
        assertEquals("we", config.authServerUrl().orElse(null));
        assertFalse(config.discoveryEnabled().orElse(false));
        assertEquals("don't", config.registrationPath().orElse(null));
        assertEquals(656, config.connectionDelay().map(Duration::getSeconds).orElse(null));
        assertEquals(565, config.connectionRetryCount());
        assertEquals(673, config.connectionTimeout().getSeconds());
        assertTrue(config.useBlockingDnsLookup());
        assertEquals(376, config.maxPoolSize().orElse(0));
        assertFalse(config.followRedirects());
        assertNotNull(config.proxy());
        assertNotNull(config.tls());
        assertEquals("Teacher!", config.tls().tlsConfigurationName().orElse(null));
        assertEquals("Kreacher!", config.proxy().proxyConfigurationName().orElse(null));
    }

    @Test
    public void testEveryPropertyIsCompared() {
        // OidcCommonConfig methods
        assertCompared(OidcTenantConfigBuilder::authServerUrl, "https://server-1", "https://server-2");
        assertCompared(OidcTenantConfigBuilder::discoveryPath, "discovery-1", "discovery-2");
        assertCompared(OidcTenantConfigBuilder::discoveryEnabled, true, false);
        assertCompared(OidcTenantConfigBuilder::registrationPath, "registration-1", "registration-2");
        assertCompared(OidcTenantConfigBuilder::connectionDelay, Duration.ofSeconds(1), Duration.ofSeconds(2));
        assertCompared(OidcTenantConfigBuilder::connectionRetryCount, 1, 2);
        assertCompared(OidcTenantConfigBuilder::connectionTimeout, Duration.ofSeconds(1), Duration.ofSeconds(2));
        assertCompared(OidcTenantConfigBuilder::useBlockingDnsLookup, true, false);
        assertCompared(OidcTenantConfigBuilder::maxPoolSize, 1, 2);
        assertCompared(OidcTenantConfigBuilder::followRedirects, true, false);
        assertCompared(OidcTenantConfigBuilder::proxyConfigurationName, "proxy-1", "proxy-2");
        assertCompared(OidcTenantConfigBuilder::tlsConfigurationName, "tls-1", "tls-2");

        // OidcClientCommonConfig methods
        assertCompared(OidcTenantConfigBuilder::tokenPath, "token-1", "token-2");
        assertCompared(OidcTenantConfigBuilder::revokePath, "revoke-1", "revoke-2");
        assertCompared(OidcTenantConfigBuilder::clientId, "client-1", "client-2");
        assertCompared(OidcTenantConfigBuilder::clientName, "client-name-1", "client-name-2");
        assertCompared((builder, secret) -> builder.credentials().secret(secret).end(), "secret-1", "secret-2");
        assertCompared((builder, forAllEndpoints) -> {
            var credentials = builder.credentials();
            if (forAllEndpoints) {
                credentials.forAllEndpoints();
            }
            credentials.end();
        }, true, false);
        assertCompared((builder, value) -> builder.credentials().clientSecret(value).end(), "value-1", "value-2");
        assertCompared((builder, method) -> builder.credentials().clientSecret().method(method).endCredentials(),
                Method.BASIC, Method.POST);
        assertCompared((builder, key) -> builder.credentials().clientSecret().provider().key(key).end().endCredentials(),
                "key-1", "key-2");
        assertCompared((builder, name) -> builder.credentials().clientSecret().provider().name(name).end().endCredentials(),
                "name-1", "name-2");
        assertCompared((builder, keyringName) -> builder.credentials().clientSecret().provider().keyringName(keyringName)
                .end().endCredentials(), "keyring-1", "keyring-2");
        assertCompared((builder, assertion) -> builder.credentials().jwt().assertion(assertion).endCredentials(), true, false);
        assertCompared((builder, audience) -> builder.credentials().jwt().audience(audience).endCredentials(),
                "audience-1", "audience-2");
        assertCompared((builder, claim) -> builder.credentials().jwt().claim("claim", claim).endCredentials(),
                "claim-1", "claim-2");
        assertCompared((builder, issuer) -> builder.credentials().jwt().issuer(issuer).endCredentials(),
                "issuer-1", "issuer-2");
        assertCompared((builder, keep) -> builder.credentials().jwt().keepAudienceTrailingSlash(keep).endCredentials(),
                true, false);
        assertCompared((builder, key) -> builder.credentials().jwt().key(key).endCredentials(), "key-1", "key-2");
        assertCompared((builder, keyFile) -> builder.credentials().jwt().keyFile(keyFile).endCredentials(),
                "key-file-1", "key-file-2");
        assertCompared((builder, keyId) -> builder.credentials().jwt().keyId(keyId).endCredentials(), "kid-1", "kid-2");
        assertCompared((builder, password) -> builder.credentials().jwt().keyPassword(password).endCredentials(),
                "key-password-1", "key-password-2");
        assertCompared((builder, keyStoreFile) -> builder.credentials().jwt().keyStoreFile(keyStoreFile).endCredentials(),
                "key-store-1", "key-store-2");
        assertCompared((builder, password) -> builder.credentials().jwt().keyStorePassword(password).endCredentials(),
                "key-store-password-1", "key-store-password-2");
        assertCompared((builder, lifespan) -> builder.credentials().jwt().lifespan(lifespan).endCredentials(), 1, 2);
        assertCompared((builder, publicKey) -> builder.credentials().jwt().publicKey(publicKey).endCredentials(),
                "public-key-1", "public-key-2");
        assertCompared((builder, file) -> builder.credentials().jwt().publicKeyFile(file).endCredentials(),
                "public-key-file-1", "public-key-file-2");
        assertCompared((builder, secret) -> builder.credentials().jwt().secret(secret).endCredentials(),
                "secret-1", "secret-2");
        assertCompared((builder, key) -> builder.credentials().jwt().secretProvider().key(key).end().endCredentials(),
                "key-1", "key-2");
        assertCompared((builder, name) -> builder.credentials().jwt().secretProvider().name(name).end().endCredentials(),
                "name-1", "name-2");
        assertCompared((builder, keyringName) -> builder.credentials().jwt().secretProvider().keyringName(keyringName)
                .end().endCredentials(), "keyring-1", "keyring-2");
        assertCompared((builder, algorithm) -> builder.credentials().jwt().signatureAlgorithm(algorithm).endCredentials(),
                "RS256", "ES256");
        assertCompared((builder, source) -> builder.credentials().jwt().source(source).endCredentials(),
                Source.CLIENT, Source.BEARER);
        assertCompared((builder, subject) -> builder.credentials().jwt().subject(subject).endCredentials(),
                "subject-1", "subject-2");
        assertCompared((builder, tokenKeyId) -> builder.credentials().jwt().tokenKeyId(tokenKeyId).endCredentials(),
                "token-kid-1", "token-kid-2");
        assertCompared((builder, tokenPath) -> builder.credentials().jwt().tokenPath(tokenPath).endCredentials(),
                Path.of("token-1"), Path.of("token-2"));
        assertCompared((builder, enabled) -> {
            var attestation = builder.credentials().attestation();
            if (enabled) {
                attestation.enabled();
            }
            attestation.end().end();
        }, true, false);
        assertCompared((builder, algorithm) -> builder.credentials().attestation().signatureAlgorithm(algorithm).end().end(),
                AttestationSignatureAlgorithm.ES384, AttestationSignatureAlgorithm.ES512);

        // OidcTenantConfig methods
        assertCompared(OidcTenantConfigBuilder::tenantId, "tenant-1", "tenant-2");
        assertCompared(OidcTenantConfigBuilder::tenantEnabled, true, false);
        assertCompared(OidcTenantConfigBuilder::applicationType, ApplicationType.WEB_APP, ApplicationType.SERVICE);
        assertCompared(OidcTenantConfigBuilder::authorizationPath, "authorization-1", "authorization-2");
        assertCompared(OidcTenantConfigBuilder::userInfoPath, "user-info-1", "user-info-2");
        assertCompared(OidcTenantConfigBuilder::introspectionPath, "introspection-1", "introspection-2");
        assertCompared(OidcTenantConfigBuilder::jwksPath, "jwks-1", "jwks-2");
        assertCompared(OidcTenantConfigBuilder::endSessionPath, "end-session-1", "end-session-2");
        assertCompared(OidcTenantConfigBuilder::tenantPaths, List.of("/tenant-1"), List.of("/tenant-2"));
        assertCompared(OidcTenantConfigBuilder::publicKey, "public-key-1", "public-key-2");
        assertCompared(OidcTenantConfigBuilder::allowTokenIntrospectionCache, true, false);
        assertCompared(OidcTenantConfigBuilder::allowUserInfoCache, true, false);
        assertCompared(OidcTenantConfigBuilder::cacheUserInfoInIdtoken, true, false);
        assertCompared(OidcTenantConfigBuilder::provider, Provider.GITHUB, Provider.GOOGLE);
        assertCompared(OidcTenantConfigBuilder::dpop, Duration.ofSeconds(1), Duration.ofSeconds(2));
        assertCompared((builder, name) -> builder.introspectionCredentials().name(name).end(), "name-1", "name-2");
        assertCompared((builder, secret) -> builder.introspectionCredentials().secret(secret).end(), "secret-1", "secret-2");
        assertCompared((builder, include) -> builder.introspectionCredentials().includeClientId(include).end(), true, false);
        assertCompared((builder, path) -> builder.roles().roleClaimPath(path).end(), "path-1", "path-2");
        assertCompared((builder, separator) -> builder.roles().roleClaimSeparator(separator).end(), ",", ";");
        assertCompared((builder, source) -> builder.roles().source(source).end(), idtoken, userinfo);
        assertCompared((builder, cacheSize) -> builder.jwks().cacheSize(cacheSize).end(), 1, 2);
        assertCompared((builder, timeToLive) -> builder.jwks().cacheTimeToLive(timeToLive).end(),
                Duration.ofSeconds(1), Duration.ofSeconds(2));
        assertCompared((builder, interval) -> builder.jwks().cleanUpTimerInterval(interval).end(),
                Duration.ofSeconds(1), Duration.ofSeconds(2));
        assertCompared((builder, resolveEarly) -> builder.jwks().resolveEarly(resolveEarly).end(), true, false);
        assertCompared((builder, tryAll) -> builder.jwks().tryAll(tryAll).end(), true, false);
        assertCompared((builder, name) -> builder.certificateChain().leafCertificateName(name).end(), "leaf-1", "leaf-2");
        assertCompared((builder, alias) -> builder.certificateChain().trustStoreCertAlias(alias).end(), "alias-1", "alias-2");
        assertCompared((builder, file) -> builder.certificateChain().trustStoreFile(file).end(),
                Path.of("store-1"), Path.of("store-2"));
        assertCompared((builder, type) -> builder.certificateChain().trustStoreFileType(type).end(), "PKCS12", "JKS");
        assertCompared((builder, password) -> builder.certificateChain().trustStorePassword(password).end(),
                "password-1", "password-2");
        assertCompared((builder, value) -> builder.codeGrant().extraParam("param", value).end(), "value-1", "value-2");
        assertCompared((builder, value) -> builder.codeGrant().header("header", value).end(), "value-1", "value-2");
        assertCompared((builder, algorithm) -> builder.tokenStateManager().encryptionAlgorithm(algorithm).end(),
                EncryptionAlgorithm.A256GCMKW, EncryptionAlgorithm.DIR);
        assertCompared((builder, required) -> builder.tokenStateManager().encryptionRequired(required).end(), true, false);
        assertCompared((builder, secret) -> builder.tokenStateManager().encryptionSecret(secret).end(),
                "secret-1", "secret-2");
        assertCompared((builder, split) -> builder.tokenStateManager().splitTokens(split).end(), true, false);
        assertCompared((builder, strategy) -> builder.tokenStateManager().strategy(strategy).end(),
                Strategy.ID_TOKEN, Strategy.ID_REFRESH_TOKENS);
        assertCompared((builder, server) -> builder.resourceMetadata().authorizationServer(server).end(),
                "server-1", "server-2");
        assertCompared((builder, enabled) -> builder.resourceMetadata().enabled(enabled).end(), true, false);
        assertCompared((builder, force) -> builder.resourceMetadata().forceHttpsScheme(force).end(), true, false);
        assertCompared((builder, resource) -> builder.resourceMetadata().resource(resource).end(),
                "resource-1", "resource-2");
        assertCompared((builder, scope) -> builder.resourceMetadata().scopes(scope).end(), "scope-1", "scope-2");
        assertCompared((builder, force) -> builder.clientIdMetadata().forceHttpsScheme(force).end(), true, false);

        // OidcTenantConfig.Logout methods
        assertCompared((builder, path) -> builder.logout().path(path).end(), "/logout-1", "/logout-2");
        assertCompared((builder, path) -> builder.logout().postLogoutPath(path).end(), "/post-logout-1", "/post-logout-2");
        assertCompared((builder, param) -> builder.logout().postLogoutUriParam(param).end(), "param-1", "param-2");
        assertCompared((builder, value) -> builder.logout().extraParam("param", value).end(), "value-1", "value-2");
        assertCompared((builder, directive) -> builder.logout().clearSiteData(List.of(directive)).end(),
                ClearSiteData.CACHE, ClearSiteData.COOKIES);
        assertCompared((builder, mode) -> builder.logout().logoutMode(mode).end(), LogoutMode.QUERY, LogoutMode.FORM_POST);
        assertCompared((builder, path) -> builder.logout().frontchannelPath(path).end(),
                "/front-channel-1", "/front-channel-2");
        assertCompared((builder, path) -> builder.logout().backchannel().path(path).endLogout(),
                "/back-channel-1", "/back-channel-2");
        assertCompared((builder, key) -> builder.logout().backchannel().logoutTokenKey(key).endLogout(), "sub", "sid");
        assertCompared((builder, size) -> builder.logout().backchannel().tokenCacheSize(size).endLogout(), 1, 2);
        assertCompared((builder, timeToLive) -> builder.logout().backchannel().tokenCacheTimeToLive(timeToLive).endLogout(),
                Duration.ofSeconds(1), Duration.ofSeconds(2));
        assertCompared((builder, interval) -> builder.logout().backchannel().cleanUpTimerInterval(interval).endLogout(),
                Duration.ofSeconds(1), Duration.ofSeconds(2));

        // OidcTenantConfig.Authentication methods
        assertCompared((builder, add) -> builder.authentication().addOpenidScope(add).end(), true, false);
        assertCompared((builder, allow) -> builder.authentication().allowMultipleCodeFlows(allow).end(), true, false);
        assertCompared((builder, noStore) -> {
            var authentication = builder.authentication();
            if (noStore) {
                authentication.cacheControl(CacheControl.NO_STORE);
            }
            authentication.end();
        }, true, false);
        assertCompared((builder, domain) -> builder.authentication().cookieDomain(domain).end(), "domain-1", "domain-2");
        assertCompared((builder, force) -> builder.authentication().cookieForceSecure(force).end(), true, false);
        assertCompared((builder, path) -> builder.authentication().cookiePath(path).end(), "/cookie-1", "/cookie-2");
        assertCompared((builder, header) -> builder.authentication().cookiePathHeader(header).end(), "header-1", "header-2");
        assertCompared((builder, sameSite) -> builder.authentication().cookieSameSite(sameSite).end(),
                CookieSameSite.STRICT, CookieSameSite.NONE);
        assertCompared((builder, suffix) -> builder.authentication().cookieSuffix(suffix).end(), "suffix-1", "suffix-2");
        assertCompared((builder, path) -> builder.authentication().errorPath(path).end(), "/error-1", "/error-2");
        assertCompared((builder, value) -> builder.authentication().extraParam("param", value).end(), "value-1", "value-2");
        assertCompared((builder, fail) -> builder.authentication().failOnMissingStateParam(fail).end(), true, false);
        assertCompared((builder, fail) -> builder.authentication().failOnUnresolvedKid(fail).end(), true, false);
        assertCompared((builder, force) -> builder.authentication().forceRedirectHttpsScheme(force).end(), true, false);
        assertCompared((builder, param) -> builder.authentication().forwardParams(param).end(), "param-1", "param-2");
        assertCompared((builder, required) -> builder.authentication().idTokenRequired(required).end(), true, false);
        assertCompared((builder, lifespan) -> builder.authentication().internalIdTokenLifespan(lifespan).end(),
                Duration.ofSeconds(1), Duration.ofSeconds(2));
        assertCompared((builder, redirect) -> builder.authentication().javaScriptAutoRedirect(redirect).end(), true, false);
        assertCompared((builder, required) -> builder.authentication().nonceRequired(required).end(), true, false);
        assertCompared((builder, enabled) -> {
            var authentication = builder.authentication();
            if (enabled) {
                authentication.par();
            }
            authentication.end();
        }, true, false);
        assertCompared((builder, path) -> builder.authentication().par(path).end(), "/par-1", "/par-2");
        assertCompared((builder, required) -> builder.authentication().pkceRequired(required).end(), true, false);
        assertCompared((builder, type) -> builder.authentication().rar(type, Map.of("key", "value")).end(),
                "type-1", "type-2");
        assertCompared((builder, path) -> builder.authentication().redirectPath(path).end(), "/redirect-1", "/redirect-2");
        assertCompared((builder, remove) -> builder.authentication().removeRedirectParameters(remove).end(), true, false);
        assertCompared((builder, mode) -> builder.authentication().responseMode(mode).end(), QUERY, FORM_POST);
        assertCompared((builder, restore) -> builder.authentication().restorePathAfterRedirect(restore).end(), true, false);
        assertCompared((builder, separator) -> builder.authentication().scopeSeparator(separator).end(), ",", ";");
        assertCompared((builder, scope) -> builder.authentication().scopes(scope).end(), "scope-1", "scope-2");
        assertCompared((builder, extension) -> builder.authentication().sessionAgeExtension(extension).end(),
                Duration.ofSeconds(1), Duration.ofSeconds(2));
        assertCompared((builder, path) -> builder.authentication().sessionExpiredPath(path).end(),
                "/expired-1", "/expired-2");
        assertCompared((builder, age) -> builder.authentication().stateCookieAge(age).end(),
                Duration.ofSeconds(1), Duration.ofSeconds(2));
        assertCompared((builder, sameSite) -> builder.authentication().stateCookieSameSite(sameSite).end(),
                CookieSameSite.STRICT, CookieSameSite.NONE);
        assertCompared((builder, secret) -> builder.authentication().stateSecret(secret).end(),
                "state-secret-1", "state-secret-2");
        assertCompared((builder, required) -> builder.authentication().userInfoRequired(required).end(), true, false);
        assertCompared((builder, verify) -> builder.authentication().verifyAccessToken(verify).end(), true, false);

        // OidcTenantConfig.Token methods
        assertCompared((builder, age) -> builder.token().age(age).end(), Duration.ofSeconds(1), Duration.ofSeconds(2));
        assertCompared((builder, allow) -> builder.token().allowJwtIntrospection(allow).end(), true, false);
        assertCompared((builder, allow) -> builder.token().allowOpaqueTokenIntrospection(allow).end(), true, false);
        assertCompared((builder, audience) -> builder.token().audience(audience).end(), "audience-1", "audience-2");
        assertCompared((builder, scheme) -> builder.token().authorizationScheme(scheme).end(), "Bearer", "DPoP");
        assertCompared((builder, certificate) -> builder.token().binding().certificate(certificate).end().end(), true, false);
        assertCompared((builder, name) -> builder.token().customizerName(name).end(), "customizer-1", "customizer-2");
        assertCompared((builder, decrypt) -> builder.token().decryptAccessToken(decrypt).end(), true, false);
        assertCompared((builder, decrypt) -> builder.token().decryptIdToken(decrypt).end(), true, false);
        assertCompared((builder, algorithm) -> builder.token().decryptionAlgorithm(algorithm).end(),
                DecryptionAlgorithm.RSA_OAEP, DecryptionAlgorithm.RSA_OAEP_256);
        assertCompared((builder, location) -> builder.token().decryptionKeyLocation(location).end(),
                "location-1", "location-2");
        assertCompared((builder, interval) -> builder.token().forcedJwkRefreshInterval(interval).end(),
                Duration.ofSeconds(1), Duration.ofSeconds(2));
        assertCompared((builder, header) -> builder.token().header(header).end(), "header-1", "header-2");
        assertCompared((builder, required) -> builder.token().issuedAtRequired(required).end(), true, false);
        assertCompared((builder, issuer) -> builder.token().issuer(issuer).end(), "issuer-1", "issuer-2");
        assertCompared((builder, grace) -> builder.token().lifespanGrace(grace).end(), 1, 2);
        assertCompared((builder, claim) -> builder.token().principalClaim(claim).end(), "claim-1", "claim-2");
        assertCompared((builder, refresh) -> builder.token().refreshExpired(refresh).end(), true, false);
        assertCompared((builder, timeToLive) -> builder.token().refreshTokenCacheTimeToLive(timeToLive).end(),
                Duration.ofSeconds(1), Duration.ofSeconds(2));
        assertCompared((builder, skew) -> builder.token().refreshTokenTimeSkew(skew).end(),
                Duration.ofSeconds(1), Duration.ofSeconds(2));
        assertCompared((builder, require) -> builder.token().requireJwtIntrospectionOnly(require).end(), true, false);
        assertCompared((builder, value) -> builder.token().requiredClaims("claim", value).end(), "value-1", "value-2");
        assertCompared((builder, algorithm) -> builder.token().signatureAlgorithm(algorithm).end(),
                SignatureAlgorithm.RS256, PS384);
        assertCompared((builder, required) -> builder.token().subjectRequired(required).end(), true, false);
        assertCompared((builder, type) -> builder.token().tokenType(type).end(), "type-1", "type-2");
        assertCompared((builder, verify) -> builder.token().verifyAccessTokenWithUserInfo(verify).end(), true, false);

        // a new property must be compared as well
        assertEquals(countProperties(io.quarkus.oidc.runtime.OidcTenantConfig.class), comparedProperties);
    }

    @SuppressWarnings("removal")
    @Test
    public void testPropertyChangedAfterCreationIsNotCompared() {
        OidcTenantConfig config = OidcTenantConfig.builder().tenantId("tenant").build();
        OidcTenantConfig sameConfig = OidcTenantConfig.builder().tenantId("tenant").build();
        // UserInfo is required when the OIDC provider metadata is discovered and UserInfo is injected
        config.getAuthentication().setUserInfoRequired(true);
        assertEquals(sameConfig, config);
    }

    private <T> void assertCompared(BiConsumer<OidcTenantConfigBuilder, T> setter, T value, T otherValue) {
        comparedProperties++;
        OidcTenantConfig config = build(setter, value);
        OidcTenantConfig sameConfig = build(setter, value);
        assertEquals(config, sameConfig);
        assertEquals(config.hashCode(), sameConfig.hashCode());
        assertNotEquals(config, build(setter, otherValue));
    }

    private static <T> OidcTenantConfig build(BiConsumer<OidcTenantConfigBuilder, T> setter, T value) {
        var builder = OidcTenantConfig.builder();
        setter.accept(builder, value);
        return builder.build();
    }

    private static int countProperties(Class<?> configGroup) {
        int properties = 0;
        for (java.lang.reflect.Method method : configGroup.getMethods()) {
            if (method.isDefault() || Modifier.isStatic(method.getModifiers()) || method.getParameterCount() > 0) {
                continue;
            }
            Class<?> type = method.getReturnType();
            boolean configGroupType = type.isInterface() && type.getName().startsWith("io.quarkus.oidc");
            properties += configGroupType ? countProperties(type) : 1;
        }
        return properties;
    }

    @Test
    public void testCopyProxyProperties() {
        var previousConfig = OidcTenantConfig.builder()
                .tenantId("copy-proxy-properties-test")
                .build();
        var newConfig = OidcTenantConfig.builder(previousConfig)
                .build();

        assertNotNull(previousConfig.proxy());
        assertEquals("copy-proxy-properties-test", newConfig.tenantId().orElse(null));
        assertNotNull(newConfig.proxy());
    }

    @Test
    public void testCopyOidcTenantConfigProperties() {
        var existingConfig = OidcTenantConfig.builder()
                // OidcTenantConfig methods
                .tenantId("test-copy-tenant-props")
                .tenantEnabled(false)
                .authorizationPath("authorization-path-test-1")
                .userInfoPath("user-info-path-test-1")
                .introspectionPath("introspection-path-test-1")
                .jwksPath("jwks-path-test-1")
                .endSessionPath("end-session-path-test-1")
                .tenantPath("tenant-path-test-1")
                .tenantPaths("tenant-path-test-2", "tenant-path-test-3")
                .publicKey("public-key-test-1")
                .allowTokenIntrospectionCache()
                .allowUserInfoCache()
                .cacheUserInfoInIdtoken()
                .provider(Provider.GOOGLE)
                .dpop(Duration.ofMinutes(4))
                // the rest of c&p tests for the OidcTenantConfig are tested in their dedicated builder tests below
                .build();

        // OidcTenantConfig methods
        assertEquals("test-copy-tenant-props", existingConfig.tenantId().orElse(null));
        assertFalse(existingConfig.tenantEnabled());
        var tenantPaths = existingConfig.tenantPaths().orElseThrow();
        assertEquals(3, tenantPaths.size());
        assertTrue(tenantPaths.contains("tenant-path-test-1"));
        assertTrue(tenantPaths.contains("tenant-path-test-2"));
        assertTrue(tenantPaths.contains("tenant-path-test-3"));
        assertTrue(existingConfig.allowTokenIntrospectionCache());
        assertTrue(existingConfig.allowUserInfoCache());
        assertTrue(existingConfig.cacheUserInfoInIdtoken().orElseThrow());
        assertEquals(Duration.ofMinutes(4), existingConfig.dpop().proofAge());

        var newConfig = OidcTenantConfig.builder(existingConfig)
                // OidcTenantConfig methods
                .enableTenant()
                .tenantPaths(List.of("tenant-path-test-4", "tenant-path-test-5"))
                .allowTokenIntrospectionCache(false)
                .allowUserInfoCache(false)
                .cacheUserInfoInIdtoken(false)
                .build();

        // OidcTenantConfig methods
        assertEquals("test-copy-tenant-props", newConfig.tenantId().orElse(null));
        assertTrue(newConfig.tenantEnabled());
        assertEquals("authorization-path-test-1", newConfig.authorizationPath().orElse(null));
        assertEquals("user-info-path-test-1", newConfig.userInfoPath().orElse(null));
        assertEquals("introspection-path-test-1", newConfig.introspectionPath().orElse(null));
        assertEquals("jwks-path-test-1", newConfig.jwksPath().orElse(null));
        assertEquals("end-session-path-test-1", newConfig.endSessionPath().orElse(null));
        tenantPaths = newConfig.tenantPaths().orElseThrow();
        assertEquals(5, tenantPaths.size());
        assertTrue(tenantPaths.contains("tenant-path-test-1"));
        assertTrue(tenantPaths.contains("tenant-path-test-2"));
        assertTrue(tenantPaths.contains("tenant-path-test-3"));
        assertTrue(tenantPaths.contains("tenant-path-test-4"));
        assertTrue(tenantPaths.contains("tenant-path-test-5"));
        assertEquals("public-key-test-1", newConfig.publicKey().orElse(null));
        assertFalse(newConfig.allowTokenIntrospectionCache());
        assertFalse(newConfig.allowUserInfoCache());
        assertFalse(newConfig.cacheUserInfoInIdtoken().orElseThrow());
        assertEquals(Provider.GOOGLE, newConfig.provider().orElse(null));
        assertEquals(Duration.ofMinutes(4), newConfig.dpop().proofAge());
    }

    @Test
    public void testCopyOidcClientCommonConfigProperties() {
        var existingConfig = OidcTenantConfig.builder()
                // OidcTenantConfig methods
                .tenantId("copy-oidc-client-common-props")
                // OidcClientCommonConfig methods
                .tokenPath("token-path-yep")
                .revokePath("revoke-path-yep")
                .clientId("client-id-yep")
                .clientName("client-name-yep")
                .credentials()
                .secret("secret-yep")
                .clientSecret()
                .method(Method.QUERY)
                .value("value-yep")
                .provider("key-yep", "name-yep", "keyring-name-yep")
                .end()
                .jwt()
                .source(Source.BEARER)
                .tokenPath(Path.of("jwt-bearer-token-path-test-1"))
                .secretProvider()
                .keyringName("jwt-keyring-name-yep")
                .key("jwt-key-yep")
                .name("jwt-name-yep")
                .end()
                .secret("jwt-secret-yep")
                .key("jwt-key-yep")
                .keyFile("jwt-key-file-yep")
                .keyStoreFile("jwt-key-store-file-yep")
                .keyStorePassword("jwt-key-store-password-yep")
                .keyId("jwt-key-id-yep")
                .keyPassword("jwt-key-pwd-yep")
                .audience("jwt-audience-yep")
                .tokenKeyId("jwt-token-key-id-yep")
                .issuer("jwt-issuer")
                .subject("jwt-subject")
                .claim("claim-one-name", "claim-one-value")
                .claims(Map.of("claim-two-name", "claim-two-value"))
                .signatureAlgorithm("ES512")
                .lifespan(852)
                .assertion(true)
                .endCredentials()
                .build();

        assertEquals("copy-oidc-client-common-props", existingConfig.tenantId().orElse(null));

        // OidcClientCommonConfig methods
        assertEquals("token-path-yep", existingConfig.tokenPath().orElse(null));
        assertEquals("revoke-path-yep", existingConfig.revokePath().orElse(null));
        assertEquals("client-id-yep", existingConfig.clientId().orElse(null));
        assertEquals("client-name-yep", existingConfig.clientName().orElse(null));
        var credentials = existingConfig.credentials();
        assertNotNull(credentials);
        assertEquals("secret-yep", credentials.secret().orElse(null));
        var clientSecret = credentials.clientSecret();
        assertNotNull(clientSecret);
        assertEquals(Method.QUERY, clientSecret.method().orElse(null));
        assertEquals("value-yep", clientSecret.value().orElse(null));
        var provider = clientSecret.provider();
        assertNotNull(provider);
        assertEquals("key-yep", provider.key().orElse(null));
        assertEquals("name-yep", provider.name().orElse(null));
        assertEquals("keyring-name-yep", provider.keyringName().orElse(null));
        var jwt = credentials.jwt();
        assertNotNull(jwt);
        assertEquals(Source.BEARER, jwt.source());
        assertEquals("jwt-secret-yep", jwt.secret().orElse(null));
        provider = jwt.secretProvider();
        assertNotNull(provider);
        assertEquals("jwt-keyring-name-yep", provider.keyringName().orElse(null));
        assertEquals("jwt-name-yep", provider.name().orElse(null));
        assertEquals("jwt-key-yep", provider.key().orElse(null));
        assertEquals("jwt-key-yep", jwt.key().orElse(null));
        assertEquals("jwt-key-file-yep", jwt.keyFile().orElse(null));
        assertEquals("jwt-key-store-file-yep", jwt.keyStoreFile().orElse(null));
        assertEquals("jwt-key-store-password-yep", jwt.keyStorePassword().orElse(null));
        assertEquals("jwt-key-id-yep", jwt.keyId().orElse(null));
        assertEquals("jwt-key-pwd-yep", jwt.keyPassword().orElse(null));
        assertEquals("jwt-audience-yep", jwt.audience().orElse(null));
        assertEquals("jwt-token-key-id-yep", jwt.tokenKeyId().orElse(null));
        assertEquals("jwt-issuer", jwt.issuer().orElse(null));
        assertEquals("jwt-subject", jwt.subject().orElse(null));
        var claims = jwt.claims();
        assertNotNull(claims);
        assertEquals(2, claims.size());
        assertTrue(claims.containsKey("claim-one-name"));
        assertEquals("claim-one-value", claims.get("claim-one-name"));
        assertTrue(claims.containsKey("claim-two-name"));
        assertEquals("claim-two-value", claims.get("claim-two-name"));
        assertEquals("ES512", jwt.signatureAlgorithm().orElse(null));
        assertEquals(852, jwt.lifespan());
        assertTrue(jwt.assertion());

        var newConfig = OidcTenantConfig.builder(existingConfig)
                // OidcClientCommonConfig methods
                .tokenPath("token-path-yep-CHANGED")
                .clientId("client-id-yep-CHANGED")
                .credentials()
                .secret("secret-yep-CHANGED")
                .clientSecret("val-1", Method.POST_JWT)
                .jwt()
                .secret("different-secret")
                .secretProvider()
                .key("jwt-key-yep-CHANGED")
                .end()
                .key("jwt-key-yep-CHANGED-2")
                .keyStoreFile("jwt-key-store-file-yep-CHANGED")
                .keyPassword("jwt-key-pwd-yep-CHANGED")
                .issuer("jwt-issuer-CHANGED")
                .claim("aaa", "bbb")
                .lifespan(333)
                .end()
                .clientSecret("val-1", Method.POST_JWT)
                .end()
                .build();

        assertEquals("copy-oidc-client-common-props", newConfig.tenantId().orElse(null));

        // OidcClientCommonConfig methods
        assertEquals("token-path-yep-CHANGED", newConfig.tokenPath().orElse(null));
        assertEquals("revoke-path-yep", newConfig.revokePath().orElse(null));
        assertEquals("client-id-yep-CHANGED", newConfig.clientId().orElse(null));
        assertEquals("client-name-yep", newConfig.clientName().orElse(null));
        credentials = newConfig.credentials();
        assertNotNull(credentials);
        assertEquals("secret-yep-CHANGED", credentials.secret().orElse(null));
        clientSecret = credentials.clientSecret();
        assertNotNull(clientSecret);
        assertEquals(Method.POST_JWT, clientSecret.method().orElse(null));
        assertEquals("val-1", clientSecret.value().orElse(null));
        provider = clientSecret.provider();
        assertNotNull(provider);
        assertEquals("key-yep", provider.key().orElse(null));
        assertEquals("name-yep", provider.name().orElse(null));
        assertEquals("keyring-name-yep", provider.keyringName().orElse(null));
        jwt = credentials.jwt();
        assertNotNull(jwt);
        assertEquals(Source.BEARER, jwt.source());
        assertEquals("different-secret", jwt.secret().orElse(null));
        provider = jwt.secretProvider();
        assertNotNull(provider);
        assertEquals("jwt-keyring-name-yep", provider.keyringName().orElse(null));
        assertEquals("jwt-name-yep", provider.name().orElse(null));
        assertEquals("jwt-key-yep-CHANGED", provider.key().orElse(null));
        assertEquals("jwt-key-yep-CHANGED-2", jwt.key().orElse(null));
        assertEquals("jwt-key-file-yep", jwt.keyFile().orElse(null));
        assertEquals("jwt-key-store-file-yep-CHANGED", jwt.keyStoreFile().orElse(null));
        assertEquals("jwt-key-store-password-yep", jwt.keyStorePassword().orElse(null));
        assertEquals("jwt-key-id-yep", jwt.keyId().orElse(null));
        assertEquals("jwt-key-pwd-yep-CHANGED", jwt.keyPassword().orElse(null));
        assertEquals("jwt-audience-yep", jwt.audience().orElse(null));
        assertEquals("jwt-token-key-id-yep", jwt.tokenKeyId().orElse(null));
        assertEquals("jwt-issuer-CHANGED", jwt.issuer().orElse(null));
        assertEquals("jwt-subject", jwt.subject().orElse(null));
        assertEquals("jwt-bearer-token-path-test-1", jwt.tokenPath().orElseThrow().toString());
        claims = jwt.claims();
        assertNotNull(claims);
        assertEquals(3, claims.size());
        assertTrue(claims.containsKey("claim-one-name"));
        assertEquals("claim-one-value", claims.get("claim-one-name"));
        assertTrue(claims.containsKey("claim-two-name"));
        assertEquals("claim-two-value", claims.get("claim-two-name"));
        assertTrue(claims.containsKey("aaa"));
        assertEquals("bbb", claims.get("aaa"));
        assertEquals("ES512", jwt.signatureAlgorithm().orElse(null));
        assertEquals(333, jwt.lifespan());
        assertTrue(jwt.assertion());
    }

    @Test
    public void testCopyOidcCommonConfigProperties() {
        var previousConfig = OidcTenantConfig.builder()
                .tenantId("common-props-test")
                .authServerUrl("we")
                .discoveryEnabled(false)
                .registrationPath("don't")
                .connectionDelay(Duration.ofSeconds(656))
                .connectionRetryCount(565)
                .connectionTimeout(Duration.ofSeconds(673))
                .useBlockingDnsLookup(true)
                .maxPoolSize(376)
                .followRedirects(false)
                .tlsConfigurationName("Teacher!")
                .proxyConfigurationName("Kreacher!")
                .build();
        var newConfig = OidcTenantConfig.builder(previousConfig)
                .discoveryEnabled(true)
                .connectionDelay(Duration.ofSeconds(753))
                .connectionTimeout(Duration.ofSeconds(357))
                .maxPoolSize(1988)
                .build();

        assertEquals("common-props-test", newConfig.tenantId().orElse(null));
        assertEquals("we", newConfig.authServerUrl().orElse(null));
        assertTrue(newConfig.discoveryEnabled().orElse(false));
        assertEquals("don't", newConfig.registrationPath().orElse(null));
        assertEquals(753, newConfig.connectionDelay().map(Duration::getSeconds).orElse(null));
        assertEquals(565, newConfig.connectionRetryCount());
        assertEquals(357, newConfig.connectionTimeout().getSeconds());
        assertTrue(newConfig.useBlockingDnsLookup());
        assertEquals(1988, newConfig.maxPoolSize().orElse(0));
        assertFalse(newConfig.followRedirects());
        assertNotNull(newConfig.proxy());
        assertNotNull(newConfig.tls());
        assertEquals("Teacher!", newConfig.tls().tlsConfigurationName().orElse(null));
        assertEquals("Kreacher!", newConfig.proxy().proxyConfigurationName().orElse(null));
    }

    @Test
    public void testCreateBuilderShortcuts() {
        OidcTenantConfig config = OidcTenantConfig.authServerUrl("auth-server-url").tenantId("shortcuts-1").build();
        assertEquals("auth-server-url", config.authServerUrl().orElse(null));
        assertEquals("shortcuts-1", config.tenantId().orElse(null));

        config = OidcTenantConfig.registrationPath("registration-path").tenantId("shortcuts-2").build();
        assertEquals("registration-path", config.registrationPath().orElse(null));
        assertEquals("shortcuts-2", config.tenantId().orElse(null));

        config = OidcTenantConfig.tokenPath("token-path").tenantId("shortcuts-3").build();
        assertEquals("token-path", config.tokenPath().orElse(null));
        assertEquals("shortcuts-3", config.tenantId().orElse(null));
    }

    @Test
    public void testCredentialsBuilder() {
        var jwt = new JwtBuilder<>()
                .secret("hush-hush")
                .build();
        var clientSecret = new SecretBuilder<>()
                .value("harry")
                .build();
        var credentials = new CredentialsBuilder<>()
                .secret("1234")
                .jwt(jwt)
                .clientSecret(clientSecret)
                .build();
        var config = OidcTenantConfig.builder().tenantId("1").credentials(credentials).build();
        var buildCredentials = config.credentials();
        assertEquals("1", config.tenantId().orElse(null));
        assertNotNull(buildCredentials);
        assertEquals("1234", buildCredentials.secret().orElse(null));
        assertEquals("hush-hush", buildCredentials.jwt().secret().orElse(null));
        assertEquals("harry", buildCredentials.clientSecret().value().orElse(null));
    }

    @Test
    public void testIntrospectionCredentialsBuilder() {
        var first = new IntrospectionCredentialsBuilder().includeClientId(false).build();
        var config1 = OidcTenantConfig.builder().tenantId("1").introspectionCredentials(first).build();
        assertFalse(config1.introspectionCredentials().includeClientId());
        assertTrue(config1.introspectionCredentials().name().isEmpty());
        assertTrue(config1.introspectionCredentials().secret().isEmpty());

        var config2Builder = OidcTenantConfig.builder(config1).introspectionCredentials("name1", "secret1");
        var config2 = config2Builder.build();
        assertFalse(config2.introspectionCredentials().includeClientId());
        assertEquals("name1", config2.introspectionCredentials().name().orElse(null));
        assertEquals("secret1", config2.introspectionCredentials().secret().orElse(null));

        var config3Builder = new IntrospectionCredentialsBuilder(config2Builder).secret("951357").end();
        var config3 = config3Builder.build();
        assertFalse(config3.introspectionCredentials().includeClientId());
        assertEquals("name1", config3.introspectionCredentials().name().orElse(null));
        assertEquals("951357", config3.introspectionCredentials().secret().orElse(null));

        assertEquals("1", config3.tenantId().orElse(null));
    }

    @Test
    public void testRolesBuilder() {
        var first = new RolesBuilder().source(accesstoken).build();
        var config1 = OidcTenantConfig.builder().tenantId("1").roles(first).build();
        assertTrue(config1.roles().roleClaimPath().isEmpty());
        assertTrue(config1.roles().roleClaimSeparator().isEmpty());
        assertEquals(accesstoken, config1.roles().source().orElse(null));

        var config2Builder = OidcTenantConfig.builder(config1).roles(userinfo, "role-claim-path-1");
        var config2 = config2Builder.build();
        assertEquals(userinfo, config2.roles().source().orElse(null));
        assertTrue(config2.roles().roleClaimSeparator().isEmpty());
        assertTrue(config2.roles().roleClaimPath().isPresent());
        var roleClaimPath = config2.roles().roleClaimPath().get();
        assertEquals(1, roleClaimPath.size());
        assertTrue(roleClaimPath.contains("role-claim-path-1"));

        var config3Builder = new RolesBuilder(config2Builder).roleClaimSeparator("!!!!").end();
        var config3 = config3Builder.build();
        assertEquals(userinfo, config3.roles().source().orElse(null));
        assertTrue(config3.roles().roleClaimPath().isPresent());
        roleClaimPath = config3.roles().roleClaimPath().get();
        assertEquals(1, roleClaimPath.size());
        assertTrue(roleClaimPath.contains("role-claim-path-1"));
        assertEquals("!!!!", config3.roles().roleClaimSeparator().orElse(null));

        assertEquals("1", config3.tenantId().orElse(null));
    }

    @Test
    public void testTokenBuilder() {
        var first = new TokenConfigBuilder()
                .audience(List.of("one", "two"))
                .requiredClaims(Map.of("I", "II"))
                .subjectRequired()
                .refreshExpired()
                .allowJwtIntrospection(false)
                .requireJwtIntrospectionOnly()
                .allowOpaqueTokenIntrospection(false)
                .verifyAccessTokenWithUserInfo()
                .build();
        var config1Builder = new OidcTenantConfigBuilder().token(first).tenantId("haha");
        var config1 = config1Builder.build();
        var builtFirst = config1.token();
        assertTrue(builtFirst.verifyAccessTokenWithUserInfo().orElseThrow());
        assertFalse(builtFirst.allowOpaqueTokenIntrospection());
        assertTrue(builtFirst.requireJwtIntrospectionOnly());
        assertFalse(builtFirst.allowJwtIntrospection());
        assertTrue(builtFirst.refreshExpired());
        assertTrue(builtFirst.subjectRequired());
        assertEquals(1, builtFirst.requiredClaims().size());
        assertEquals("II", builtFirst.requiredClaims().get("I").iterator().next());
        assertEquals(2, builtFirst.audience().orElseThrow().size());
        assertTrue(builtFirst.audience().orElseThrow().contains("one"));
        assertTrue(builtFirst.audience().orElseThrow().contains("two"));

        var second = new TokenConfigBuilder(config1Builder)
                .requiredClaims(Map.of("III", "IV"))
                .audience("extra");
        var config2 = second.end()
                .token().verifyAccessTokenWithUserInfo(false).principalClaim("prince").end()
                .build();
        var builtSecond = config2.token();
        assertFalse(builtSecond.verifyAccessTokenWithUserInfo().orElseThrow());
        assertFalse(builtSecond.allowOpaqueTokenIntrospection());
        assertTrue(builtSecond.requireJwtIntrospectionOnly());
        assertFalse(builtSecond.allowJwtIntrospection());
        assertTrue(builtSecond.refreshExpired());
        assertTrue(builtSecond.subjectRequired());
        assertEquals(2, builtSecond.requiredClaims().size());
        assertEquals("II", builtSecond.requiredClaims().get("I").iterator().next());
        assertEquals("IV", builtSecond.requiredClaims().get("III").iterator().next());
        assertEquals(3, builtSecond.audience().orElseThrow().size());
        assertTrue(builtSecond.audience().orElseThrow().contains("one"));
        assertTrue(builtSecond.audience().orElseThrow().contains("two"));
        assertTrue(builtSecond.audience().orElseThrow().contains("extra"));
        assertEquals("prince", builtSecond.principalClaim().orElse(null));

        var config3 = OidcTenantConfig.builder(config2).token().verifyAccessTokenWithUserInfo().end().build();
        assertTrue(config3.token().verifyAccessTokenWithUserInfo().orElseThrow());

        assertEquals("haha", config3.tenantId().orElse(null));
    }

    @Test
    public void testLogoutConfigBuilder() {
        var first = new LogoutConfigBuilder().postLogoutPath("post-logout-path-AAA").path("path-BBB")
                .frontchannelPath("front-channel-path-7").extraParams(Map.of("ex-1-k", "ex-1-v"))
                .postLogoutUriParam("uri-param-44").backchannel().logoutTokenKey("log-me-out").end().build();
        var config1 = OidcTenantConfig.builder().tenantId("tenant-357").logout(first).build();
        var builtFirst = config1.logout();

        assertEquals("post-logout-path-AAA", builtFirst.postLogoutPath().orElse(null));
        assertEquals("path-BBB", builtFirst.path().orElse(null));
        assertEquals("front-channel-path-7", builtFirst.frontchannel().path().orElse(null));
        assertEquals(1, builtFirst.extraParams().size());
        assertEquals("ex-1-v", builtFirst.extraParams().get("ex-1-k"));
        assertEquals("uri-param-44", builtFirst.postLogoutUriParam());
        assertEquals("log-me-out", builtFirst.backchannel().logoutTokenKey());

        var second = new LogoutConfigBuilder(OidcTenantConfig.builder(config1)).backchannel().path("path-CCC").endLogout();
        var config2 = second.build();
        var builtSecond = config2.logout();

        assertEquals("post-logout-path-AAA", builtSecond.postLogoutPath().orElse(null));
        assertEquals("path-BBB", builtSecond.path().orElse(null));
        assertEquals("front-channel-path-7", builtSecond.frontchannel().path().orElse(null));
        assertEquals(1, builtSecond.extraParams().size());
        assertEquals("ex-1-v", builtSecond.extraParams().get("ex-1-k"));
        assertEquals("uri-param-44", builtSecond.postLogoutUriParam());
        assertEquals("log-me-out", builtSecond.backchannel().logoutTokenKey());
        assertEquals("path-CCC", builtSecond.backchannel().path().orElse(null));

        var newBackchannel = new BackchannelBuilder().tokenCacheSize(555).build();
        var third = new LogoutConfigBuilder().backchannel(newBackchannel).build();
        var config3 = OidcTenantConfig.builder(config2).logout(third).build();

        // expect defaults everywhere except for the backchannel  token cache size
        var builtThird = config3.logout();
        assertNotNull(builtThird);
        assertTrue(builtThird.path().isEmpty());
        assertTrue(builtThird.postLogoutPath().isEmpty());
        assertEquals(OidcConstants.POST_LOGOUT_REDIRECT_URI, builtThird.postLogoutUriParam());
        assertTrue(builtThird.extraParams().isEmpty());

        var backchannel = builtThird.backchannel();
        assertNotNull(backchannel);
        assertTrue(backchannel.path().isEmpty());
        assertEquals(555, backchannel.tokenCacheSize());
        assertEquals(10, backchannel.tokenCacheTimeToLive().toMinutes());
        assertTrue(backchannel.cleanUpTimerInterval().isEmpty());
        assertEquals("sub", backchannel.logoutTokenKey());

        var frontchannel = builtThird.frontchannel();
        assertNotNull(frontchannel);
        assertTrue(frontchannel.path().isEmpty());

        assertEquals("tenant-357", config3.tenantId().orElse(null));
    }

    @Test
    public void testCertificateChainBuilder() {
        var first = new CertificateChainBuilder()
                .leafCertificateName("ent")
                .trustStoreFileType("try")
                .trustStoreFile(Path.of("march"))
                .trustStoreCertAlias("to")
                .trustStorePassword("Isengard")
                .build();
        var config1 = OidcTenantConfig.builder().tenantId("2").certificateChain(first).build();
        var builtFirst = config1.certificateChain();

        assertEquals("ent", builtFirst.leafCertificateName().orElse(null));
        assertEquals("try", builtFirst.trustStoreFileType().orElse(null));
        assertTrue(builtFirst.trustStoreFile().toString().contains("march"));
        assertEquals("to", builtFirst.trustStoreCertAlias().orElse(null));
        assertEquals("Isengard", builtFirst.trustStorePassword().orElse(null));

        var secondBuilder = new CertificateChainBuilder(new OidcTenantConfigBuilder(config1))
                .leafCertificateName("fangorn").end();
        var config2 = secondBuilder.build();
        var builtSecond = config2.certificateChain();

        assertEquals("fangorn", builtSecond.leafCertificateName().orElse(null));
        assertEquals("try", builtSecond.trustStoreFileType().orElse(null));
        assertTrue(builtSecond.trustStoreFile().toString().contains("march"));
        assertEquals("to", builtSecond.trustStoreCertAlias().orElse(null));
        assertEquals("Isengard", builtSecond.trustStorePassword().orElse(null));

        var config3 = OidcTenantConfig.builder(config2).certificateChain().trustStorePassword("home").end().build();
        var builtThird = config3.certificateChain();

        assertEquals("fangorn", builtThird.leafCertificateName().orElse(null));
        assertEquals("try", builtThird.trustStoreFileType().orElse(null));
        assertTrue(builtThird.trustStoreFile().toString().contains("march"));
        assertEquals("to", builtThird.trustStoreCertAlias().orElse(null));
        assertEquals("home", builtThird.trustStorePassword().orElse(null));

        assertEquals("2", config3.tenantId().orElse(null));
    }

    @Test
    public void testCopyOfAuthenticationConfigBuilder() {
        var first = new AuthenticationConfigBuilder()
                .responseMode(QUERY)
                .redirectPath("/redirect-path-auth-yep")
                .restorePathAfterRedirect()
                .removeRedirectParameters(false)
                .errorPath("/error-path-auth-yep")
                .sessionExpiredPath("/session-expired-path-auth-yep")
                .verifyAccessToken()
                .forceRedirectHttpsScheme()
                .scopes(List.of("scope-one", "scope-two", "scope-three"))
                .scopeSeparator("scope-separator-654456")
                .nonceRequired()
                .addOpenidScope(false)
                .extraParam("ex-auth-param-6-key", "ex-auth-param-6-val")
                .extraParam("ex-auth-param-7-key", "ex-auth-param-7-val")
                .forwardParams("forward-param-6-key", "forward-param-6-val")
                .forwardParams("forward-param-7-key", "forward-param-7-val")
                .cookieForceSecure()
                .cookieSuffix("cookie-suffix-auth-whatever")
                .cookiePath("/cookie-path-auth-whatever")
                .cookiePathHeader("cookie-path-header-auth-whatever")
                .cookieDomain("cookie-domain-auth-whatever")
                .cookieSameSite(CookieSameSite.NONE)
                .allowMultipleCodeFlows(false)
                .failOnMissingStateParam()
                .userInfoRequired()
                .sessionAgeExtension(Duration.ofMinutes(77))
                .stateCookieAge(Duration.ofMinutes(88))
                .javaScriptAutoRedirect(false)
                .idTokenRequired(false)
                .internalIdTokenLifespan(Duration.ofMinutes(357))
                .pkceRequired()
                .stateSecret("state-secret-auth-whatever")
                .par()
                .build();
        var config1Builder = OidcTenantConfig.builder().tenantId("3").authentication(first);
        var config1 = config1Builder.build();
        var builtFirst = config1.authentication();

        var forwardParams = builtFirst.forwardParams().orElseThrow();
        assertEquals(4, forwardParams.size());
        assertTrue(forwardParams.contains("forward-param-6-key"));
        assertTrue(forwardParams.contains("forward-param-7-key"));
        assertTrue(forwardParams.contains("forward-param-6-val"));
        assertTrue(forwardParams.contains("forward-param-7-val"));
        var extraParams = builtFirst.extraParams();
        assertEquals(2, extraParams.size());
        assertEquals("ex-auth-param-6-val", extraParams.get("ex-auth-param-6-key"));
        assertEquals("ex-auth-param-7-val", extraParams.get("ex-auth-param-7-key"));
        var scopes = builtFirst.scopes().orElseThrow();
        assertEquals(3, scopes.size());
        assertTrue(scopes.contains("scope-one"));
        assertTrue(scopes.contains("scope-two"));
        assertTrue(scopes.contains("scope-three"));
        assertEquals("scope-separator-654456", builtFirst.scopeSeparator().orElseThrow());
        assertEquals(QUERY, builtFirst.responseMode().orElseThrow());
        assertEquals("/session-expired-path-auth-yep", builtFirst.sessionExpiredPath().orElseThrow());
        assertEquals("/error-path-auth-yep", builtFirst.errorPath().orElseThrow());
        assertEquals("/redirect-path-auth-yep", builtFirst.redirectPath().orElseThrow());
        assertFalse(builtFirst.removeRedirectParameters());
        assertTrue(builtFirst.restorePathAfterRedirect());
        assertTrue(builtFirst.verifyAccessToken());
        assertTrue(builtFirst.forceRedirectHttpsScheme().orElseThrow());
        assertTrue(builtFirst.nonceRequired());
        assertFalse(builtFirst.addOpenidScope().orElseThrow());
        assertTrue(builtFirst.cookieForceSecure());
        assertEquals("cookie-suffix-auth-whatever", builtFirst.cookieSuffix().orElse(null));
        assertEquals("/cookie-path-auth-whatever", builtFirst.cookiePath());
        assertEquals("cookie-path-header-auth-whatever", builtFirst.cookiePathHeader().orElseThrow());
        assertEquals("cookie-domain-auth-whatever", builtFirst.cookieDomain().orElseThrow());
        assertEquals(CookieSameSite.NONE, builtFirst.cookieSameSite());
        assertFalse(builtFirst.allowMultipleCodeFlows());
        assertTrue(builtFirst.failOnMissingStateParam());
        assertTrue(builtFirst.userInfoRequired().orElseThrow());
        assertEquals(77, builtFirst.sessionAgeExtension().get().toMinutes());
        assertEquals(88, builtFirst.stateCookieAge().toMinutes());
        assertFalse(builtFirst.javaScriptAutoRedirect());
        assertFalse(builtFirst.idTokenRequired().orElseThrow());
        assertEquals(357, builtFirst.internalIdTokenLifespan().orElseThrow().toMinutes());
        assertTrue(builtFirst.pkceRequired().orElseThrow());
        assertEquals("state-secret-auth-whatever", builtFirst.stateSecret().orElse(null));
        assertTrue(builtFirst.par().enabled().orElse(false));
        assertTrue(builtFirst.par().path().isEmpty());

        var second = new AuthenticationConfigBuilder(config1Builder).scopes("scope-four").responseMode(FORM_POST)
                .extraParams(Map.of("ho", "hey")).stateSecret("my-state-secret");
        var config2 = second.end().build();
        var builtSecond = config2.authentication();

        forwardParams = builtSecond.forwardParams().orElseThrow();
        assertEquals(4, forwardParams.size());
        assertTrue(forwardParams.contains("forward-param-6-key"));
        assertTrue(forwardParams.contains("forward-param-7-key"));
        assertTrue(forwardParams.contains("forward-param-6-val"));
        assertTrue(forwardParams.contains("forward-param-7-val"));
        extraParams = builtSecond.extraParams();
        assertEquals(3, extraParams.size());
        assertEquals("ex-auth-param-6-val", extraParams.get("ex-auth-param-6-key"));
        assertEquals("ex-auth-param-7-val", extraParams.get("ex-auth-param-7-key"));
        assertEquals("hey", extraParams.get("ho"));
        scopes = builtSecond.scopes().orElseThrow();
        assertEquals(4, scopes.size());
        assertTrue(scopes.contains("scope-one"));
        assertTrue(scopes.contains("scope-two"));
        assertTrue(scopes.contains("scope-three"));
        assertTrue(scopes.contains("scope-four"));
        assertEquals("scope-separator-654456", builtSecond.scopeSeparator().orElseThrow());
        assertEquals(FORM_POST, builtSecond.responseMode().orElseThrow());
        assertEquals("/session-expired-path-auth-yep", builtSecond.sessionExpiredPath().orElseThrow());
        assertEquals("/error-path-auth-yep", builtSecond.errorPath().orElseThrow());
        assertEquals("/redirect-path-auth-yep", builtSecond.redirectPath().orElseThrow());
        assertFalse(builtSecond.removeRedirectParameters());
        assertTrue(builtSecond.restorePathAfterRedirect());
        assertTrue(builtSecond.verifyAccessToken());
        assertTrue(builtSecond.forceRedirectHttpsScheme().orElseThrow());
        assertTrue(builtSecond.nonceRequired());
        assertFalse(builtSecond.addOpenidScope().orElseThrow());
        assertTrue(builtSecond.cookieForceSecure());
        assertEquals("cookie-suffix-auth-whatever", builtSecond.cookieSuffix().orElse(null));
        assertEquals("/cookie-path-auth-whatever", builtSecond.cookiePath());
        assertEquals("cookie-path-header-auth-whatever", builtSecond.cookiePathHeader().orElseThrow());
        assertEquals("cookie-domain-auth-whatever", builtSecond.cookieDomain().orElseThrow());
        assertEquals(CookieSameSite.NONE, builtSecond.cookieSameSite());
        assertFalse(builtSecond.allowMultipleCodeFlows());
        assertTrue(builtSecond.failOnMissingStateParam());
        assertTrue(builtSecond.userInfoRequired().orElseThrow());
        assertEquals(77, builtSecond.sessionAgeExtension().get().toMinutes());
        assertEquals(88, builtSecond.stateCookieAge().toMinutes());
        assertFalse(builtSecond.javaScriptAutoRedirect());
        assertFalse(builtSecond.idTokenRequired().orElseThrow());
        assertEquals(357, builtSecond.internalIdTokenLifespan().orElseThrow().toMinutes());
        assertTrue(builtSecond.pkceRequired().orElseThrow());
        assertEquals("my-state-secret", builtSecond.stateSecret().orElse(null));
        assertTrue(builtSecond.par().enabled().orElse(false));
        assertTrue(builtSecond.par().path().isEmpty());
    }

    @Test
    public void testCodeGrantBuilder() {
        var first = new CodeGrantBuilder()
                .extraParams(Map.of("code-grant-param", "code-grant-param-val"))
                .headers(Map.of("code-grant-header", "code-grant-header-val"))
                .build();
        var config1 = new OidcTenantConfigBuilder().tenantId("7").codeGrant(first).build();
        var builtFirst = config1.codeGrant();
        assertEquals(1, builtFirst.extraParams().size());
        assertEquals("code-grant-param-val", builtFirst.extraParams().get("code-grant-param"));
        assertEquals(1, builtFirst.headers().size());
        assertEquals("code-grant-header-val", builtFirst.headers().get("code-grant-header"));

        var config2 = new CodeGrantBuilder(OidcTenantConfig.builder(config1))
                .extraParam("1", "one")
                .header("2", "two")
                .end()
                .build();
        var builtSecond = config2.codeGrant();
        assertEquals(2, builtSecond.extraParams().size());
        assertEquals("code-grant-param-val", builtSecond.extraParams().get("code-grant-param"));
        assertEquals("one", builtSecond.extraParams().get("1"));
        assertEquals(2, builtSecond.headers().size());
        assertEquals("code-grant-header-val", builtSecond.headers().get("code-grant-header"));
        assertEquals("two", builtSecond.headers().get("2"));

        var config3 = OidcTenantConfig.builder(config2).codeGrant(Map.of("new", "header")).build();
        var builtThird = config3.codeGrant();
        assertEquals(2, builtThird.extraParams().size());
        assertEquals("code-grant-param-val", builtThird.extraParams().get("code-grant-param"));
        assertEquals("one", builtThird.extraParams().get("1"));
        assertEquals(3, builtThird.headers().size());
        assertEquals("code-grant-header-val", builtThird.headers().get("code-grant-header"));
        assertEquals("two", builtThird.headers().get("2"));
        assertEquals("header", builtThird.headers().get("new"));

        var config4 = OidcTenantConfig.builder(config3).codeGrant(Map.of("old", "header"), Map.of("new", "extra")).build();
        var builtFourth = config4.codeGrant();
        assertEquals(3, builtFourth.extraParams().size());
        assertEquals("code-grant-param-val", builtFourth.extraParams().get("code-grant-param"));
        assertEquals("one", builtFourth.extraParams().get("1"));
        assertEquals("extra", builtFourth.extraParams().get("new"));
        assertEquals(4, builtFourth.headers().size());
        assertEquals("code-grant-header-val", builtFourth.headers().get("code-grant-header"));
        assertEquals("two", builtFourth.headers().get("2"));
        assertEquals("header", builtFourth.headers().get("new"));
        assertEquals("header", builtFourth.headers().get("old"));

        assertEquals("7", config4.tenantId().orElse(null));
    }

    @Test
    public void testTokenStateManagerBuilder() {
        var first = new TokenStateManagerBuilder()
                .strategy(Strategy.ID_REFRESH_TOKENS)
                .splitTokens()
                .encryptionRequired(false)
                .encryptionSecret("1-enc-secret")
                .encryptionAlgorithm(EncryptionAlgorithm.DIR)
                .build();
        var config1 = new OidcTenantConfigBuilder().tenantId("6").tokenStateManager(first).build();
        var builtFirst = config1.tokenStateManager();
        assertEquals(Strategy.ID_REFRESH_TOKENS, builtFirst.strategy());
        assertTrue(builtFirst.splitTokens());
        assertFalse(builtFirst.encryptionRequired());
        assertEquals("1-enc-secret", builtFirst.encryptionSecret().orElse(null));
        assertEquals(EncryptionAlgorithm.DIR, builtFirst.encryptionAlgorithm());

        var second = new TokenStateManagerBuilder(new OidcTenantConfigBuilder(config1))
                .encryptionRequired()
                .splitTokens(false);
        var config2 = second.end().build();
        var builtSecond = config2.tokenStateManager();
        assertEquals(Strategy.ID_REFRESH_TOKENS, builtSecond.strategy());
        assertFalse(builtSecond.splitTokens());
        assertTrue(builtSecond.encryptionRequired());
        assertEquals("1-enc-secret", builtSecond.encryptionSecret().orElse(null));
        assertEquals(EncryptionAlgorithm.DIR, builtSecond.encryptionAlgorithm());

        assertEquals("6", config2.tenantId().orElse(null));
    }

    @Test
    public void testJwksBuilder() {
        var first = new JwksBuilder()
                .resolveEarly(false)
                .cacheSize(67)
                .cacheTimeToLive(Duration.ofMinutes(5784))
                .cleanUpTimerInterval(Duration.ofMinutes(47568))
                .tryAll()
                .build();
        var config1 = new OidcTenantConfigBuilder().tenantId("87").jwks(first).build();
        var builtFirst = config1.jwks();
        assertTrue(builtFirst.tryAll());
        assertFalse(builtFirst.resolveEarly());
        assertEquals(67, builtFirst.cacheSize());
        assertEquals(5784, builtFirst.cacheTimeToLive().toMinutes());
        assertEquals(47568, builtFirst.cleanUpTimerInterval().orElseThrow().toMinutes());

        var config2 = new JwksBuilder(new OidcTenantConfigBuilder(config1))
                .resolveEarly()
                .tryAll(false)
                .end().build();
        var builtSecond = config2.jwks();
        assertFalse(builtSecond.tryAll());
        assertTrue(builtSecond.resolveEarly());
        assertEquals(67, builtSecond.cacheSize());
        assertEquals(5784, builtSecond.cacheTimeToLive().toMinutes());
        assertEquals(47568, builtSecond.cleanUpTimerInterval().orElseThrow().toMinutes());

        assertEquals("87", config2.tenantId().orElse(null));
    }
}
