package io.quarkus.spiffe.client.runtime.internal;

import java.net.Socket;
import java.net.URI;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.CertPathValidator;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.function.Function;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509ExtendedKeyManager;
import javax.net.ssl.X509ExtendedTrustManager;
import javax.net.ssl.X509KeyManager;

import org.jboss.logging.Logger;

import io.quarkus.runtime.configuration.ConfigurationException;
import io.quarkus.spiffe.client.SpiffeConnectionException;
import io.quarkus.spiffe.svid.x509.WorkloadCertificateDocument;
import io.quarkus.spiffe.svid.x509.X509Svid;
import io.quarkus.tls.TlsConfiguration;
import io.vertx.core.Vertx;
import io.vertx.core.net.ClientSSLOptions;
import io.vertx.core.net.KeyCertOptions;
import io.vertx.core.net.PqcEnforcementPolicy;
import io.vertx.core.net.SSLEngineOptions;
import io.vertx.core.net.SSLOptions;
import io.vertx.core.net.ServerSSLOptions;
import io.vertx.core.net.TrustOptions;

/**
 * TLS configuration backed by the workload X.509-SVID.
 * <p>
 * The configuration holds no certificate material. Its key manager and trust manager look up the current
 * {@link WorkloadCertificateDocument} in the {@link SpiffeTlsConfigurationManager} at handshake time, so all
 * SPIFFE TLS configurations share one X.509-SVID and one trust bundle and differ only by name and by the peer
 * {@link #spiffeId()} they authorize. A rotated SVID or trust bundle is picked up by the next handshake, which is
 * why consumers never need to reload this configuration.
 * <p>
 * Peer validation follows the X.509-SVID specification, section 5: standard RFC 5280 path validation against the
 * trust bundle, SPIFFE leaf validation and SPIFFE ID authorization. Hostname verification does not apply, SPIFFE
 * conveys the peer identity in the URI SAN.
 * <p>
 * The key manager and the trust manager are their own Vert.x {@link KeyCertOptions} and {@link TrustOptions}:
 * Vert.x caches SSL contexts by options equality, and returning the same instances guarantees that a consumer
 * which keeps asking for the options never triggers an SSL context rebuild.
 */
record SpiffeTlsConfiguration(String tlsConfigurationName, String spiffeId,
        SpiffeTlsConfigurationManager tlsConfigurationManager, SpiffeTlsConfiguration.SpiffeKeyManager keyManager,
        SpiffeTlsConfiguration.SpiffeTrustManager trustManager) implements TlsConfiguration {

    // (not done - the reload period belongs to the manager / caching client, there is nothing to validate here)
    //   TODO: validate reload period is lower than svid ttl
    // (not done - build-time validation belongs to the processor and the config mapping)
    //   TODO: validate reload period correct period during the build time
    // (not done - needs a runtime check of the 'quarkus.tls.<name>.*' property names before the registration;
    //   SpiffeTlsConfigurationSupplier#get is the natural place, see /tmp/spiffe-tls/ISSUES.md item 7)
    //   TODO: validate that tls config of this name is not configured by user otherwise fail
    // (done - SpiffeClientProcessor fails the build when the TLS registry capability is missing)
    //   TODO: validate TLS registry present or fail build
    // (done - getTrustStoreOptions, getClientSSLOptions, getServerSSLOptions and createSSLContext all go through
    //   SpiffeTrustManager; the raw stores throw, as a raw store cannot carry the authorization)
    //   TODO: ensure all methods are enforcing spiffe id authorization check
    // (done - the syntax is validated in the compact constructor; membership in the workload trust domain can only be
    //   checked once the SVID is known, so it is enforced on every handshake instead)
    //   TODO: validate spiffe id
    // (done - getSslEngineOptions, reload, createSSLContext, getClientSSLOptions, getServerSSLOptions,
    //   getTrustStoreOptions, getKeyStoreOptions)
    //   TODO: impl. me!

    private static final Logger LOG = Logger.getLogger(SpiffeTlsConfiguration.class);

    /**
     * Same defaults as a {@code quarkus.tls.<name>} bucket that only configures its stores.
     */
    private static final String TLS_PROTOCOL = "TLSv1.3";
    private static final long HANDSHAKE_TIMEOUT_SECONDS = 10;
    /**
     * The TLS registry marker for disabled hostname verification; consumers such as the REST client test for it on
     * both {@link #getHostnameVerificationAlgorithm()} and {@link ClientSSLOptions#getHostnameVerificationAlgorithm()}.
     */
    private static final String NO_HOSTNAME_VERIFICATION = "NONE";

    SpiffeTlsConfiguration {
        if (tlsConfigurationName == null || tlsConfigurationName.isBlank()) {
            throw new ConfigurationException(
                    "The TLS configuration name of an @" + X509Svid.class.getSimpleName() + " declaration must not be blank");
        }
        Objects.requireNonNull(tlsConfigurationManager,
                "The SPIFFE TLS configuration manager must be initialized before the TLS configuration '"
                        + tlsConfigurationName + "' is created");
        if (!X509Svid.SAME_TRUST_DOMAIN.equals(spiffeId)) {
            try {
                SpiffeValidator.validateSpiffeId(spiffeId);
            } catch (SpiffeConnectionException e) {
                throw new ConfigurationException("Invalid peer SPIFFE ID '" + spiffeId + "' of the TLS configuration '"
                        + tlsConfigurationName + "': " + e.getMessage(), e);
            }
        }
        Objects.requireNonNull(keyManager, "keyManager");
        Objects.requireNonNull(trustManager, "trustManager");
    }

    SpiffeTlsConfiguration(String tlsConfigurationName, String spiffeId,
            SpiffeTlsConfigurationManager tlsConfigurationManager) {
        this(tlsConfigurationName, spiffeId, tlsConfigurationManager,
                new SpiffeKeyManager(tlsConfigurationName, tlsConfigurationManager),
                new SpiffeTrustManager(tlsConfigurationName, spiffeId, tlsConfigurationManager));
    }

    @Override
    public String getName() {
        return tlsConfigurationName;
    }

    @Override
    public KeyCertOptions getKeyStoreOptions() {
        return keyManager;
    }

    @Override
    public TrustOptions getTrustStoreOptions() {
        return trustManager;
    }

    @Override
    public KeyStore getKeyStore() {
        throw new UnsupportedOperationException(
                "SPIFFE X.509-SVID TLS configurations do not expose a raw key store, as consumers of it build their own "
                        + "TLS context that skips SPIFFE ID authorization; use getKeyStoreOptions() instead.");
    }

    @Override
    public KeyStore getTrustStore() {
        throw new UnsupportedOperationException(
                "SPIFFE X.509-SVID TLS configurations do not expose a raw trust store, as it cannot enforce "
                        + "SPIFFE ID authorization; use getTrustStoreOptions() instead.");
    }

    @Override
    public ServerSSLOptions getServerSSLOptions() {
        ServerSSLOptions options = new ServerSSLOptions();
        populate(options);
        options.setSni(false);
        // client authentication stays with the consumer, for example 'quarkus.http.ssl.client-auth'; without it the
        // trust manager is never asked to authorize clients
        return options;
    }

    @Override
    public ClientSSLOptions getClientSSLOptions() {
        ClientSSLOptions options = new ClientSSLOptions();
        populate(options);
        options.setTrustAll(false);
        options.setHostnameVerificationAlgorithm(NO_HOSTNAME_VERIFICATION);
        return options;
    }

    private void populate(SSLOptions options) {
        options.setKeyCertOptions(keyManager);
        options.setTrustOptions(trustManager);
        options.setUseAlpn(true);
        options.setPqcEnforcementPolicy(PqcEnforcementPolicy.RELAXED);
        options.setSslHandshakeTimeoutUnit(TimeUnit.SECONDS);
        options.setSslHandshakeTimeout(HANDSHAKE_TIMEOUT_SECONDS);
        // a mutable set, consumers may add protocols to the options they received
        options.setEnabledSecureTransportProtocols(new LinkedHashSet<>(List.of(TLS_PROTOCOL)));
    }

    @Override
    public SSLContext createSSLContext() throws Exception {
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(new KeyManager[] { keyManager }, new TrustManager[] { trustManager }, null);
        return sslContext;
    }

    @Override
    public boolean isTrustAll() {
        return false;
    }

    @Override
    public Optional<String> getHostnameVerificationAlgorithm() {
        return Optional.of(NO_HOSTNAME_VERIFICATION);
    }

    @Override
    public boolean usesSni() {
        return false;
    }

    @Override
    public boolean reload() {
        // the key and trust managers read the current X.509-SVID on every handshake, there is nothing to reload
        return false;
    }

    @Override
    public Optional<SSLEngineOptions> getSslEngineOptions() {
        return Optional.empty();
    }

    private static String trustDomainOf(String spiffeId) {
        // the SPIFFE ID has been validated, the authority is the trust domain
        return URI.create(spiffeId).getHost();
    }

    /**
     * Presents the workload X.509-SVID. The JSSE asks for the alias first and for the private key and the certificate
     * chain afterwards; the alias identifies the document, so that a rotation in between never pairs a new key with
     * an old chain.
     */
    static final class SpiffeKeyManager extends X509ExtendedKeyManager implements KeyCertOptions {

        private static final String ALIAS_PREFIX = "spiffe-";

        private final String tlsConfigurationName;
        private final SpiffeTlsConfigurationManager manager;
        private volatile WorkloadCertificateDocument lastChosen;
        private volatile WorkloadCertificateDocument previouslyChosen;

        private SpiffeKeyManager(String tlsConfigurationName, SpiffeTlsConfigurationManager manager) {
            this.tlsConfigurationName = tlsConfigurationName;
            this.manager = manager;
        }

        @Override
        public String[] getClientAliases(String keyType, Principal[] issuers) {
            return aliases(keyType);
        }

        @Override
        public String chooseClientAlias(String[] keyTypes, Principal[] issuers, Socket socket) {
            return chooseAlias(keyTypes);
        }

        @Override
        public String chooseEngineClientAlias(String[] keyTypes, Principal[] issuers, SSLEngine engine) {
            return chooseAlias(keyTypes);
        }

        @Override
        public String[] getServerAliases(String keyType, Principal[] issuers) {
            return aliases(keyType);
        }

        @Override
        public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket) {
            return chooseAlias(new String[] { keyType });
        }

        @Override
        public String chooseEngineServerAlias(String keyType, Principal[] issuers, SSLEngine engine) {
            return chooseAlias(new String[] { keyType });
        }

        @Override
        public X509Certificate[] getCertificateChain(String alias) {
            WorkloadCertificateDocument document = document(alias);
            return document == null ? null : document.certificateChain().chain().toArray(new X509Certificate[0]);
        }

        @Override
        public PrivateKey getPrivateKey(String alias) {
            WorkloadCertificateDocument document = document(alias);
            return document == null ? null : document.certificateChain().privateKey();
        }

        @Override
        public KeyCertOptions copy() {
            return this;
        }

        @Override
        public KeyManagerFactory getKeyManagerFactory(Vertx vertx) throws Exception {
            return KeyCertOptions.wrap((X509KeyManager) this).getKeyManagerFactory(vertx);
        }

        @Override
        public Function<String, KeyManagerFactory> keyManagerFactoryMapper(Vertx vertx) {
            // no SNI, Vert.x falls back to getKeyManagerFactory
            return serverName -> null;
        }

        @Override
        public String toString() {
            return "SpiffeKeyManager[" + tlsConfigurationName + "]";
        }

        private String[] aliases(String keyType) {
            String alias = chooseAlias(new String[] { keyType });
            return alias == null ? null : new String[] { alias };
        }

        private String chooseAlias(String[] keyTypes) {
            WorkloadCertificateDocument document = manager.getWorkloadCertificateDocument();
            if (document == null) {
                LOG.warnf("No X.509-SVID is available, the TLS configuration '%s' cannot present a certificate",
                        tlsConfigurationName);
                return null;
            }
            String keyAlgorithm = document.certificateChain().privateKey().getAlgorithm();
            if (keyTypes == null || !supports(keyAlgorithm, keyTypes)) {
                LOG.debugf("The X.509-SVID key algorithm '%s' is not among the key types %s requested by the peer of the "
                        + "TLS configuration '%s'", keyAlgorithm, keyTypes == null ? null : List.of(keyTypes),
                        tlsConfigurationName);
                return null;
            }
            if (document != lastChosen) {
                previouslyChosen = lastChosen;
                lastChosen = document;
            }
            return alias(document);
        }

        private static boolean supports(String keyAlgorithm, String[] keyTypes) {
            for (String keyType : keyTypes) {
                if (keyAlgorithm.equalsIgnoreCase(keyType)
                        || ("RSASSA-PSS".equalsIgnoreCase(keyType) && "RSA".equalsIgnoreCase(keyAlgorithm))) {
                    return true;
                }
            }
            return false;
        }

        private WorkloadCertificateDocument document(String alias) {
            if (alias == null) {
                return null;
            }
            WorkloadCertificateDocument[] candidates = { lastChosen, previouslyChosen,
                    manager.getWorkloadCertificateDocument() };
            for (WorkloadCertificateDocument candidate : candidates) {
                if (candidate != null && alias.equals(alias(candidate))) {
                    return candidate;
                }
            }
            return null;
        }

        private static String alias(WorkloadCertificateDocument document) {
            return ALIAS_PREFIX + document.certificateChain().chain().get(0).getSerialNumber().toString(16);
        }
    }

    /**
     * Validates and authorizes peer X.509-SVIDs. It extends {@link X509ExtendedTrustManager} on purpose: the JSSE
     * performs hostname verification itself around a plain {@link javax.net.ssl.X509TrustManager}, which would reject
     * every SVID.
     */
    static final class SpiffeTrustManager extends X509ExtendedTrustManager implements TrustOptions {

        private static final String ANY_EXTENDED_KEY_USAGE = "2.5.29.37.0";
        private static final String SERVER_AUTH = "1.3.6.1.5.5.7.3.1";
        private static final String CLIENT_AUTH = "1.3.6.1.5.5.7.3.2";

        private enum Peer {
            /** The peer is a TLS client, this workload is the server. */
            CLIENT("client", CLIENT_AUTH),
            /** The peer is a TLS server, this workload is the client. */
            SERVER("server", SERVER_AUTH);

            private final String description;
            private final String extendedKeyUsage;

            Peer(String description, String extendedKeyUsage) {
                this.description = description;
                this.extendedKeyUsage = extendedKeyUsage;
            }
        }

        private final String tlsConfigurationName;
        private final String spiffeId;
        private final SpiffeTlsConfigurationManager manager;

        private SpiffeTrustManager(String tlsConfigurationName, String spiffeId, SpiffeTlsConfigurationManager manager) {
            this.tlsConfigurationName = tlsConfigurationName;
            this.spiffeId = spiffeId;
            this.manager = manager;
        }

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
            validate(chain, Peer.CLIENT);
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
            validate(chain, Peer.SERVER);
        }

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType, Socket socket)
                throws CertificateException {
            validate(chain, Peer.CLIENT);
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType, Socket socket)
                throws CertificateException {
            validate(chain, Peer.SERVER);
        }

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType, SSLEngine engine)
                throws CertificateException {
            validate(chain, Peer.CLIENT);
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType, SSLEngine engine)
                throws CertificateException {
            validate(chain, Peer.SERVER);
        }

        /**
         * A hint for peers that select their certificate by issuer, never used for validation.
         */
        @Override
        public X509Certificate[] getAcceptedIssuers() {
            WorkloadCertificateDocument document = manager.getWorkloadCertificateDocument();
            if (document == null) {
                return new X509Certificate[0];
            }
            return document.trustBundle().certificates().toArray(new X509Certificate[0]);
        }

        @Override
        public TrustOptions copy() {
            return this;
        }

        @Override
        public TrustManagerFactory getTrustManagerFactory(Vertx vertx) throws Exception {
            return TrustOptions.wrap((TrustManager) this).getTrustManagerFactory(vertx);
        }

        @Override
        public Function<String, TrustManager[]> trustManagerMapper(Vertx vertx) {
            // no SNI, Vert.x falls back to getTrustManagerFactory
            return serverName -> null;
        }

        @Override
        public String toString() {
            return "SpiffeTrustManager[" + tlsConfigurationName + ", " + spiffeId + "]";
        }

        private void validate(X509Certificate[] chain, Peer peer) throws CertificateException {
            if (chain == null || chain.length == 0) {
                throw reject(peer, "it presented no certificate", null);
            }
            X509Certificate leaf = chain[0];

            // X.509-SVID 5.2: leaf validation and exactly one URI SAN with a valid SPIFFE ID
            String peerSpiffeId;
            try {
                peerSpiffeId = SpiffeValidator.validateLeaf(leaf);
                SpiffeValidator.validateSpiffeId(peerSpiffeId);
            } catch (SpiffeConnectionException e) {
                throw reject(peer, "its certificate is not a valid X.509-SVID: " + e.getMessage(), e);
            }
            // X.509-SVID 4.4: when the extension is present, it must allow the TLS role of the peer
            List<String> extendedKeyUsage = leaf.getExtendedKeyUsage();
            if (extendedKeyUsage != null && !extendedKeyUsage.contains(ANY_EXTENDED_KEY_USAGE)
                    && !extendedKeyUsage.contains(peer.extendedKeyUsage)) {
                throw reject(peer, "the extended key usage of its certificate does not allow TLS " + peer.description
                        + " authentication", null);
            }

            WorkloadCertificateDocument document = manager.getWorkloadCertificateDocument();
            if (document == null) {
                throw reject(peer, "no X.509-SVID trust bundle is available", null);
            }
            // SPIFFE Workload API 4.6: validate against the bundle of the trust domain of the peer; a peer whose trust
            // domain has no bundle is untrusted, and only the bundle of the workload trust domain is available
            String peerTrustDomain = trustDomainOf(peerSpiffeId);
            String trustDomain = trustDomainOf(document.subject());
            if (!peerTrustDomain.equals(trustDomain)) {
                throw reject(peer, "there is no trust bundle for its trust domain '" + peerTrustDomain
                        + "', only the trust domain '" + trustDomain + "' is trusted", null);
            }
            // X.509-SVID 5.1: RFC 5280 path validation against the trust bundle
            validatePath(chain, document.trustBundle().certificates(), peer);

            if (!X509Svid.SAME_TRUST_DOMAIN.equals(spiffeId) && !spiffeId.equals(peerSpiffeId)) {
                LOG.warnf("The TLS configuration '%s' rejected the %s with the SPIFFE ID '%s', it only authorizes '%s'",
                        tlsConfigurationName, peer.description, peerSpiffeId, spiffeId);
                throw new CertificateException("The " + peer.description + " SPIFFE ID '" + peerSpiffeId
                        + "' is not authorized by the TLS configuration '" + tlsConfigurationName + "'");
            }
            LOG.debugf("The TLS configuration '%s' authorized the %s with the SPIFFE ID '%s'", tlsConfigurationName,
                    peer.description, peerSpiffeId);
        }

        private void validatePath(X509Certificate[] chain, List<X509Certificate> trustBundle, Peer peer)
                throws CertificateException {
            Set<TrustAnchor> trustAnchors = new HashSet<>();
            for (X509Certificate ca : trustBundle) {
                trustAnchors.add(new TrustAnchor(ca, null));
            }
            // a peer may send a CA certificate of the bundle along; PKIX wants the path without its trust anchor
            List<X509Certificate> path = new ArrayList<>(chain.length);
            for (X509Certificate certificate : chain) {
                if (trustBundle.contains(certificate)) {
                    break;
                }
                path.add(certificate);
            }
            if (path.isEmpty()) {
                throw reject(peer, "it presented a trust bundle CA certificate as its own certificate", null);
            }
            try {
                PKIXParameters parameters = new PKIXParameters(trustAnchors);
                parameters.setRevocationEnabled(false);
                CertPathValidator.getInstance("PKIX")
                        .validate(CertificateFactory.getInstance("X.509").generateCertPath(path), parameters);
            } catch (GeneralSecurityException e) {
                throw reject(peer, "its certificate chain does not chain to the trust bundle: " + e.getMessage(), e);
            }
        }

        private CertificateException reject(Peer peer, String reason, Exception cause) {
            String message = "The TLS configuration '" + tlsConfigurationName + "' rejected the " + peer.description
                    + ": " + reason;
            LOG.debug(message);
            return new CertificateException(message, cause);
        }
    }
}
