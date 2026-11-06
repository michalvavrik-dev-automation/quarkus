package io.quarkus.spiffe.client.runtime.internal;

import java.util.function.Consumer;

import io.quarkus.spiffe.client.SpiffeConnectionException;
import io.quarkus.spiffe.svid.x509.WorkloadCertificateDocument;
import io.quarkus.spiffe.svid.x509.X509SvidClient;

public final class SpiffeTlsConfigurationManager {

    private static volatile SpiffeTlsConfigurationManager INSTANCE = null;

    private final X509SvidCachingClient x509SvidClient;

    private SpiffeTlsConfigurationManager(X509SvidClient x509SvidClient) {
        this.x509SvidClient = new X509SvidCachingClient((short) 50, x509SvidClient); // FIXME: this casting to short is suspicious
    }

    public void initialize(Runnable onComplete, Consumer<Throwable> onFailure) {
        // TODO: we should handle case when something requests tls config before we do
        // TODO: we need to handle situations when workload certificate is not ready? we need to retry but
        //      - on the first request when the certificate is used we fail
        //      - within some timeout from the following subscription:
        x509SvidClient.getWorkloadCertificate().subscribe().with(
                ignored -> onComplete.run(),
                failure -> onFailure.accept(new SpiffeConnectionException(
                        "Failed to obtain X509 SVID", failure // Fixme: BETTER EXCEPTION
                )));
        // not needed anymore
        SpiffeTlsConfigurationManager.INSTANCE = null;
    }

    private void close() {
        // FIXME: impl. me! avoid race with initialize method
        x509SvidClient.close();
        // FIXME: once the client is closed, we should try to do something with the tls configuration like TRUST NOONE and log warning - illegal state
    }

    // TODO: expose method that provide truststore options / manager / factory or whatever based on the spiffe id
    //      however it must be cancellable when TLL runs out we need to deny and probably even switch / reload?

    public static SpiffeTlsConfigurationManager createFrom(Consumer<Runnable> registerStopAction,
            X509SvidClient x509SvidClient) {
        var provider = new SpiffeTlsConfigurationManager(x509SvidClient);
        registerStopAction.accept(provider::close);
        SpiffeTlsConfigurationManager.INSTANCE = provider;
        return provider;
    }

    WorkloadCertificateDocument getWorkloadCertificateDocument() {
        return x509SvidClient.getCurrentWorkloadCertificate();
    }

    static SpiffeTlsConfigurationManager get() {
        return INSTANCE;
    }
}
