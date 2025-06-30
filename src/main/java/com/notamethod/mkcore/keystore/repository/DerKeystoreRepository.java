package com.notamethod.mkcore.keystore.repository;



import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import com.notamethod.mkcore.certificate.Certificate;
import com.notamethod.mkcore.keystore.KeyStoreValue;
import com.notamethod.mkcore.utils.ServiceException;
import com.notamethod.mkcore.keystore.MKKeystoreValue;
import com.notamethod.mkcore.keystore.StoreFormat;

import java.io.*;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.*;

class DerKeystoreRepository extends AbstractSimpleAbstractKeystoreRepository implements MkKeystore {

    private static final Logger log = LogManager.getLogger(DerKeystoreRepository.class);


    public DerKeystoreRepository() {
        this.format= StoreFormat.DER;
    }


    @Override
    public void savePrivateKey(PrivateKey privateKey, String fName, char[] pass) throws ServiceException {
        try {

            byte[] privKey = privateKey.getEncoded();

// binary ?
            try (FileOutputStream keyfos = new FileOutputStream(fName + ".key")) {
                keyfos.write(privKey);
            }

        } catch (Exception e) {
            throw new ServiceException("Fail to export private key", e);
        }

    }

    @Override
    public void saveCertificates(KeyStoreValue ksValue, List<Certificate> certInfos) {

    }

    @Override
    public void save(MKKeystoreValue ksValue, SAVE_OPTION option) throws RepositoryException {

        File file = new File(ksValue.getPath());
        if (file.exists() && option.equals(SAVE_OPTION.NONE)) {
            throw new RepositoryException("File already exists " + file.getAbsolutePath());
        }
        try {
            try (FileOutputStream keyfos = new FileOutputStream(file)) {
                for (Certificate certInfo : ksValue.getCertificates()) {
                    keyfos.write(certInfo.getX509Certificate().getEncoded());
                }
            }
        } catch (Exception e) {
            throw new RepositoryException("Can't save file", e);
        }
    }



    @Override
    public List<Certificate> getCertificates(MKKeystoreValue ksValue) {
        if (ksValue.getCertificates() != null && !ksValue.getCertificates().isEmpty())
            return ksValue.getCertificates();

        List<Certificate> certsRetour = new ArrayList<>();
        //  InputStream is = null;
        try (InputStream is = new FileInputStream(ksValue.getPath())) {
            //  is = new FileInputStream(new File(ksValue.getPath()));

            CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");

            // chargement du certificat
            Collection<X509Certificate> certs = (Collection<X509Certificate>) cf.generateCertificates(is);
            for (X509Certificate cert : certs) {
                Certificate certInfo = new Certificate(null, cert);

                certsRetour.add(certInfo);
            }

        } catch (GeneralSecurityException | IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        ksValue.setCertificates(certsRetour);
        return certsRetour;
    }

    @Override
    public void addCert(KeyStoreValue ki, Certificate certificate) {

    }




}
