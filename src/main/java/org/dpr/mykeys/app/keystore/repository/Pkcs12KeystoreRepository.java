package org.dpr.mykeys.app.keystore.repository;



import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.dpr.mykeys.app.certificate.Certificate;
import org.dpr.mykeys.app.keystore.KeyStoreValue;
import org.dpr.mykeys.app.keystore.StoreFormat;

import java.security.PrivateKey;
import java.util.List;

class Pkcs12KeystoreRepository extends AbstractJavaKeystoreRepository {

    private static final Logger log = LogManager.getLogger(JksKeystoreRepository.class);

    public Pkcs12KeystoreRepository() {
        this.format = StoreFormat.PKCS12;
    }

    @Override
    public void savePrivateKey(PrivateKey privateKey, String fName, char[] pass) {

    }

    @Override
    public void saveCertificates(KeyStoreValue ksValue, List<Certificate> certInfos) {

    }


    @Override
    protected StoreFormat getFormat() {
        return format;
    }
}
