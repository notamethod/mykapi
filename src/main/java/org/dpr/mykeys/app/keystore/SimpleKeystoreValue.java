package org.dpr.mykeys.app.keystore;

import org.dpr.mykeys.app.certificate.CertificateValue;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

public class SimpleKeystoreValue implements MKKeystoreValue {
    private final List<CertificateValue> certificates = new ArrayList<>();
    protected String path;
    protected StoreFormat storeFormat;

    public SimpleKeystoreValue(String path, StoreFormat format) {
        this.path = new File(path).getPath();
        this.storeFormat = format;
    }

    public String getPath() {
        return path;
    }

    public void setPath(String path) {
        this.path = path;
    }

    @Override
    public List<CertificateValue> getCertificates() {
        return certificates;
    }

    @Override
    public void setCertificates(List<CertificateValue> certificates) {
        this.certificates.clear();
        this.certificates.addAll(certificates);
    }
}
