package org.dpr.mykeys.app.keystore;

import org.dpr.mykeys.app.certificate.Certificate;
import org.dpr.mykeys.app.common.CryptoObject;

import java.util.List;

//FIXME
public interface MKKeystoreValue {

    List<Certificate> getCertificates();
    void setCertificates(List<Certificate> certificates);
    String getPath();
    void setPath(String path);
    boolean isLoaded();
    void setLoaded(boolean loaded);
    StoreFormat getStoreFormat() ;
     void setStoreFormat(StoreFormat storeFormat);
     List<CryptoObject> getElements();

}
