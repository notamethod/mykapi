package org.dpr.mykeys.app.keystore;

import org.dpr.mykeys.app.certificate.CertificateValue;

import java.util.List;

public interface MKKeystoreValue {
    List<CertificateValue> getCertificates();
    void setCertificates(List<CertificateValue> certificates);
    String getPath();
    void setPath(String path);
}
