package io.quarkus.spiffe.client.runtime.internal;

import io.quarkus.spiffe.svid.x509.WorkloadCertificateDocument;
import io.quarkus.spiffe.svid.x509.X509SvidClient;
import io.smallrye.mutiny.Uni;

final class X509SvidCachingClient implements X509SvidClient {

    // TODO: what do we do when at that time there is not a new certificate? we keep trying until expired, but then?
    //          probably null
    private final short reloadPeriod; // FIXME: rename, must reflect that this is %
    private final X509SvidClient delegate;
    private volatile WorkloadCertificateDocument workloadCertificateDocument;

    X509SvidCachingClient(short reloadPeriod, X509SvidClient delegate) {
        // TODO: on one hand we need to keep the reload period configurable so that the blame is not us if
        //      if certificates are rotated before it stops being "valid" (aka early rotation, I think effective revocation is not done in SPIRE)
        //      but on the other hand it makes a little sense to reload after cert is not valid so probably we need to make it some value
        //      that is always "value before it expires"? and we need to validate it based on the real cert that arrives and do what? probably log something

        this.reloadPeriod = reloadPeriod;
        this.delegate = delegate;
    }

    @Override
    public Uni<WorkloadCertificateDocument> getWorkloadCertificate() {
        // FIXME: impl. me!
        return delegate.getWorkloadCertificate().invoke(c -> X509SvidCachingClient.this.workloadCertificateDocument = c);
    }

    WorkloadCertificateDocument getCurrentWorkloadCertificate() {
        return workloadCertificateDocument;
    }

    void close() {
        // FIXME: impl. me!
        this.workloadCertificateDocument = null;
    }
}
