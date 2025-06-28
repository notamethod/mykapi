package org.dpr.mykeys.app.keystore.repository;



import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.dpr.mykeys.app.keystore.KeyToolsException;
import org.dpr.mykeys.app.certificate.Certificate;
import org.dpr.mykeys.app.keystore.KeyStoreValue;
import org.dpr.mykeys.app.keystore.StoreFormat;

import java.io.*;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.List;

class JksKeystoreRepository extends AbstractJavaKeystoreRepository {

    private static final Logger log = LogManager.getLogger(JksKeystoreRepository.class);

    //protected final StoreFormat format = StoreFormat.JKS;

    public JksKeystoreRepository() {
        this.format = StoreFormat.JKS;
    }


    @Override
    public void removeCertificates(KeyStoreValue ksValue, List<Certificate> certificates) throws RepositoryException{

        try {

            if (null == ksValue.getKeystore()) {

                ksValue.setKeystore(loadJavaKeyStore(ksValue.getPath(), ksValue.getStoreFormat(), ksValue.getPassword()));
            }
            List<Certificate> certs = getCertificates(ksValue);

            for (Certificate certificateInfo : certificates) {
                if (certificateInfo != null) {
                    certs.remove(certificateInfo);
                    ksValue.getKeystore().deleteEntry(certificateInfo.getAlias());
                }
            }
            saveKeyStore(ksValue.getKeystore(), ksValue.getPath(), ksValue.getPassword());

        } catch (Exception e) {
            throw new RepositoryException(e);
        }
    }

    @Override
    public void savePrivateKey(PrivateKey privateKey, String fName, char[] pass) {

    }

    @Override
    public void saveCertificates(KeyStoreValue ksValue, List<Certificate> certInfos) {

    }



    public void saveKeyStore(KeyStore ks, String path, char[] password) throws KeyToolsException {

        try {
            ks.aliases();
            OutputStream fos = new FileOutputStream(path);
            ks.store(fos, password);
            fos.close();
        } catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException e) {
            throw new KeyToolsException("Echec de sauvegarde du magasin impossible:" + path, e);
        }
    }


    private KeyStore getKeyStore(KeyStoreValue ksValue) throws RepositoryException {
        if (null == ksValue.getKeystore()) {
            ksValue.setKeystore(loadJavaKeyStore(ksValue.getPath(), ksValue.getStoreFormat(), ksValue.getPassword()));
        }
        return ksValue.getKeystore();
    }

    @Override
    protected StoreFormat getFormat() {
        return format;
    }

    public void changeAlias(String oldAlias, String newAlias){
        //FIXME: implementMethod
    }
}
