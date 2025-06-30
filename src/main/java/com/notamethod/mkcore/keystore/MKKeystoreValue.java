package com.notamethod.mkcore.keystore;

import com.notamethod.mkcore.certificate.Certificate;
import com.notamethod.mkcore.common.CryptoObject;

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
