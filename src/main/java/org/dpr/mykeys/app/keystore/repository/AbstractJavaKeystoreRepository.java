package org.dpr.mykeys.app.keystore.repository;

import org.apache.commons.io.FileUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.dpr.mykeys.app.KeyToolsException;
import org.dpr.mykeys.app.certificate.CertificateValue;
import org.dpr.mykeys.app.keystore.KeyStoreValue;
import org.dpr.mykeys.app.keystore.KeystoreBuilder;
import org.dpr.mykeys.app.ServiceException;
import org.dpr.mykeys.app.keystore.MKKeystoreValue;
import org.dpr.mykeys.app.keystore.StoreFormat;

import java.io.*;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

public abstract class AbstractJavaKeystoreRepository extends KeystoreRepository {

    private static final Log log = LogFactory.getLog(AbstractJavaKeystoreRepository.class);

    public MKKeystoreValue create(String name, char[] password) throws RepositoryException, IOException {

        Path path = Paths.get(name);
        if (path.toFile().exists()) {
            throw new IOException("File already exists " + path.toString());
        }
        try {
            KeyStore keystore = KeyStore.getInstance(format.toString());
            keystore.load(null, password);
            OutputStream fos = new FileOutputStream(new File(name));
            keystore.store(fos, password);
            fos.close();
        } catch (Exception e) {
            throw new RepositoryException(e);
        }

        MKKeystoreValue keyStoreValue = new KeyStoreValue(name, format);

        return keyStoreValue;
    }

    @Override
    public void addCertificates(KeyStoreValue ksValue, List<CertificateValue> certificates) throws RepositoryException {
        try {
            KeyStore ks = loadJavaKeyStore(ksValue.getPath(), ksValue.getStoreFormat(), ksValue.getPassword());
            KeystoreBuilder ksb = new KeystoreBuilder(ks);
            ksb.addCerts(ksValue, certificates);
        } catch (KeyToolsException e) {
            throw new RepositoryException("addCerts fail", e);
        }
    }


    @Override
    public MKKeystoreValue load(String name, char[] password) throws RepositoryException, IOException {
        KeyStoreValue keystoreValue = new KeyStoreValue(new File(name), this.format, password);

        keystoreValue.setKeystore(loadJavaKeyStore(name, format, password));
        keystoreValue.setCertificates(getCertificates(keystoreValue));
        return keystoreValue;
    }

    /**
     * @param ksName
     * @param format
     * @param pwd
     * @return
     * @throws KeyToolsException
     */
    KeyStore loadJavaKeyStore(String ksName, StoreFormat format, char[] pwd) throws RepositoryException {
        String type = StoreFormat.getValue(format);
        KeyStore ks;
        try {
            try {
                ks = KeyStore.getInstance(type, "BC");
            } catch (Exception e) {
                ks = KeyStore.getInstance("JKS");
            }

            // get user password and file input stream
            java.io.FileInputStream fis = new java.io.FileInputStream(ksName);
            ks.load(fis, pwd);
            fis.close();
        } catch (KeyStoreException e) {
            throw new RepositoryException("Fail to load:" + ksName, e);
        } catch (FileNotFoundException e) {
            throw new RepositoryException("File not found:" + ksName + ", " + e.getCause(), e);
        } catch (NoSuchAlgorithmException e) {
            throw new RepositoryException("Format unknown:" + ksName + ", " + e.getCause(), e);
        } catch (CertificateException | IOException e) {
            throw new RepositoryException("Fail to load:" + ksName + ", " + e.getCause(), e);
        }
        return ks;
    }

    @Override
    public void save(MKKeystoreValue inKsValue, SAVE_OPTION option) throws RepositoryException {

        KeyStoreValue ksValue = (KeyStoreValue) inKsValue;
        File file = new File(ksValue.getPath());
        boolean exists = file.exists();
        try {
            if (exists) {
                switch (option) {
                    case NONE:
                        throw new EntityAlreadyExistsException("File already exists " + file.getAbsolutePath());
                    case REPLACE:
                        FileUtils.deleteQuietly(file);
                        create(ksValue.getPath(), ((KeyStoreValue) ksValue).getPassword());

                        break;
                    case ADD:
                        //loadJavaKeyStore(ksValue.getPath(), getFormat(), ksValue.getPassword());
                        break;
                    default:
                        //nothing
                        break;
                }
            } else {
                create(ksValue.getPath(), ksValue.getPassword());
            }

        } catch (Exception e) {
            throw new RepositoryException("creating fail", e);
        }

        try {
            KeyStore ks = loadJavaKeyStore(ksValue.getPath(), ksValue.getStoreFormat(), ksValue.getPassword());
            KeystoreBuilder ksb = new KeystoreBuilder(ks);
            ksb.addCerts(ksValue, ksValue.getCertificates());
        } catch (KeyToolsException e) {
            throw new RepositoryException("addCerts fail", e);
        }


    }

    public List<CertificateValue> getCertificates(MKKeystoreValue mksValue) throws RepositoryException {

        KeyStoreValue ksValue = (KeyStoreValue) mksValue;
        if (ksValue.getCertificates() != null && !ksValue.getCertificates().isEmpty())
            return ksValue.getCertificates();
        else {
            if (null == ksValue.getKeystore()) {

                ksValue.setKeystore(loadJavaKeyStore(ksValue.getPath(), ksValue.getStoreFormat(), ksValue.getPassword()));
            }
            KeyStore ks = ksValue.getKeystore();
            List<CertificateValue> certs = new ArrayList<>();

            Enumeration<String> enumKs;
            try {
                enumKs = ks.aliases();
                if (enumKs != null && enumKs.hasMoreElements()) {

                    while (enumKs.hasMoreElements()) {
                        String alias = enumKs.nextElement();

                        CertificateValue certInfo = fillCertInfo(ks, alias);
                        certs.add(certInfo);
                    }
                }
            } catch (KeyStoreException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            }
            ksValue.setCertificates(certs);
            return certs;
        }
    }

    /**
     * Must be deleted because of CertificateValue constructor
     *
     * @param ks
     * @param alias
     * @return
     * @throws ServiceException
     */
    private CertificateValue fillCertInfo(KeyStore ks, String alias) throws RepositoryException {
        CertificateValue certInfo;
        try {
            Certificate certificate = ks.getCertificate(alias);
            Certificate[] certs = ks.getCertificateChain(alias);

            certInfo = new CertificateValue(alias, (X509Certificate) certificate);
            if (ks.isKeyEntry(alias)) {
                certInfo.setContainsPrivateKey(true);

            }
            StringBuilder bf = new StringBuilder();
            if (certs == null) {
                String message = "certification chain is null for " + alias + " (" + certInfo.getName() + ")";
                if (certInfo.isContainsPrivateKey())
                    log.error(message);
                else
                    log.debug(message);
            } else {
                for (Certificate chainCert : certs) {
                    bf.append(chainCert.toString());
                }
                certInfo.setChaineStringValue(bf.toString());
                certInfo.setCertificateChain(certs);
            }

        } catch (GeneralSecurityException e) {
            throw new RepositoryException("filling certificate Info impossible", e);
        }
        return certInfo;
    }

    public void addCert(KeyStoreValue ksValue, CertificateValue certificate) throws RepositoryException {
        KeyStore ks = loadJavaKeyStore(ksValue.getPath(), ksValue.getStoreFormat(), ksValue.getPassword());
        KeystoreBuilder ksb = new KeystoreBuilder(ks);
        try {
            ksb.addCert(ksValue, certificate);
            ksValue.getCertificates().add(certificate);
        } catch (KeyToolsException e) {
            throw new RepositoryException("addCerts fail", e);
        }

    }


    protected abstract StoreFormat getFormat();

}
