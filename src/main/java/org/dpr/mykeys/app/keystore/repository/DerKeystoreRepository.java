package org.dpr.mykeys.app.keystore.repository;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.dpr.mykeys.app.certificate.CertificateValue;
import org.dpr.mykeys.app.keystore.KeyStoreValue;
import org.dpr.mykeys.app.ServiceException;
import org.dpr.mykeys.app.keystore.MKKeystoreValue;
import org.dpr.mykeys.app.keystore.StoreFormat;

import java.io.*;
import java.security.GeneralSecurityException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.*;

class DerKeystoreRepository extends AbstractSimpleKeystoreRepository implements MkKeystore {

    private static final Log log = LogFactory.getLog(DerKeystoreRepository.class);


    public DerKeystoreRepository() {
        this.format= StoreFormat.DER;
    }


    @Override
    public void savePrivateKey(PrivateKey privateKey, String fName, char[] pass) throws ServiceException {
        try {

            byte[] privKey = privateKey.getEncoded();

// binary ?
            try (FileOutputStream keyfos = new FileOutputStream(new File(fName + ".key"))) {
                keyfos.write(privKey);
            }

        } catch (Exception e) {
            throw new ServiceException("Fail to export private key", e);
        }

    }

    @Override
    public void saveCertificates(KeyStoreValue ksValue, List<CertificateValue> certInfos) {

    }

    @Override
    public void save(MKKeystoreValue ksValue, SAVE_OPTION option) throws RepositoryException {

        File file = new File(ksValue.getPath());
        if (file.exists() && option.equals(SAVE_OPTION.NONE)) {
            throw new RepositoryException("File already exists " + file.getAbsolutePath());
        }
        try {
            try (FileOutputStream keyfos = new FileOutputStream(file)) {
                for (CertificateValue certInfo : ksValue.getCertificates()) {
                    keyfos.write(certInfo.getCertificate().getEncoded());
                }
            }
        } catch (Exception e) {
            throw new RepositoryException("Can't save file", e);
        }
    }



    @Override
    public List<CertificateValue> getCertificates(MKKeystoreValue ksValue) {
        if (ksValue.getCertificates() != null && !ksValue.getCertificates().isEmpty())
            return ksValue.getCertificates();

        List<CertificateValue> certsRetour = new ArrayList<>();
        //  InputStream is = null;
        try (InputStream is = new FileInputStream(new File(ksValue.getPath()))) {
            //  is = new FileInputStream(new File(ksValue.getPath()));

            CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");

            // chargement du certificat
            Collection<X509Certificate> certs = (Collection<X509Certificate>) cf.generateCertificates(is);
            Set<X509Certificate> certificates = new HashSet<>(certs);
            for (X509Certificate cert : certs) {
                CertificateValue certInfo = new CertificateValue(null, cert);

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
    public void addCert(KeyStoreValue ki, CertificateValue certificate) {

    }




}
