package org.dpr.mykeys.app.keystore.repository;

import org.apache.commons.io.FileUtils;


import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.dpr.mykeys.app.keystore.KeyToolsException;
import org.dpr.mykeys.app.certificate.Certificate;
import org.dpr.mykeys.app.keystore.KeyStoreValue;
import org.dpr.mykeys.app.keystore.KeystoreBuilder;
import org.dpr.mykeys.app.keystore.MKKeystoreValue;
import org.dpr.mykeys.app.keystore.StoreFormat;

import java.io.*;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

public abstract class AbstractJavaKeystoreRepository extends AbstractKeystoreRepository {

    private static final Logger log = LogManager.getLogger(AbstractJavaKeystoreRepository.class);
    private boolean storePassword = true;
    static final String ADDCERT_ERROR="Adding certificate(s) fails";

    public MKKeystoreValue create(String name, char[] password) throws RepositoryException, IOException {

        Path path = Paths.get(name);
        if (path.toFile().exists()) {
            throw new IOException("File already exists " + path.toString());
        }
        try {
            KeyStore keystore = KeyStore.getInstance(format.toString());
            keystore.load(null, password);
            OutputStream fos = new FileOutputStream(name);
            keystore.store(fos, password);
            fos.close();
        } catch (Exception e) {
            throw new RepositoryException(e);
        }

        KeyStoreValue keyStoreValue = new KeyStoreValue(name, format);
        if (storePassword)
            keyStoreValue.setPassword(password);
        return keyStoreValue;
    }

    /**
     * add certificates to keystore. Keystore is saved
     * @param ksValue target keystore
     * @param certificates list of certificates to add
     * @throws RepositoryException
     */
    @Override
    public void addCertificates(MKKeystoreValue ksValue, List<Certificate> certificates) throws RepositoryException {
        try {
            KeyStore ks = loadJavaKeyStore(ksValue.getPath(), ksValue.getStoreFormat(), ((KeyStoreValue)ksValue).getPassword());
            KeystoreBuilder ksb = new KeystoreBuilder(ks);
            ksb.addCerts((KeyStoreValue) ksValue, certificates);
            //FIXME: add or not ?
            ksValue.getCertificates().addAll(certificates);
        } catch (KeyToolsException e) {
            throw new RepositoryException(ADDCERT_ERROR, e);
        }
    }


    /**
     *
     * load a keystore from a file and open it with password
     * @param name
     * @param password
     * @return an opened MKKeystoreValue object
     * @throws RepositoryException
     * @throws IOException
     */
    @Override
    public MKKeystoreValue load(String name, char[] password) throws RepositoryException {
        KeyStoreValue keystoreValue = new KeyStoreValue(new File(name), this.format, password);
        keystoreValue.setOpen(true);
        keystoreValue.setLoaded(true);
        keystoreValue.setKeystore(loadJavaKeyStore(name, format, password));
        keystoreValue.setCertificates(getCertificates(keystoreValue));
        if (storePassword)
            keystoreValue.setPassword(password);
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
                ks = KeyStore.getInstance(type);
            }

            // get user password and file input stream
            try(java.io.FileInputStream fis = new java.io.FileInputStream(ksName)){
                ks.load(fis, pwd);
            }


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
                        create(ksValue.getPath(), ksValue.getPassword());

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

        } catch (IOException e) {
            throw new RepositoryException("writing file failed", e);
        }

        try {
            KeyStore ks = loadJavaKeyStore(ksValue.getPath(), ksValue.getStoreFormat(), ksValue.getPassword());
            KeystoreBuilder ksb = new KeystoreBuilder(ks);
            ksb.addCerts(ksValue, ksValue.getCertificates());
        } catch (KeyToolsException e) {
            throw new RepositoryException(ADDCERT_ERROR, e);
        }


    }

    public List<Certificate> getCertificates(MKKeystoreValue mksValue) throws RepositoryException {

        KeyStoreValue ksValue = (KeyStoreValue) mksValue;
        if (ksValue.getCertificates() != null && !ksValue.getCertificates().isEmpty())
            return ksValue.getCertificates();
        else {
            if (null == ksValue.getKeystore()) {

                ksValue.setKeystore(loadJavaKeyStore(ksValue.getPath(), ksValue.getStoreFormat(), ksValue.getPassword()));
            }

            KeyStore ks = ksValue.getKeystore();
            List<Certificate> certs = new ArrayList<>();

            Enumeration<String> enumKs;
            try {
                enumKs = ks.aliases();
                if (enumKs != null && enumKs.hasMoreElements()) {

                    while (enumKs.hasMoreElements()) {
                        String alias = enumKs.nextElement();

                        Certificate certInfo = fillCertInfo(ks, alias);
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

    public PrivateKey getPrivateKey(MKKeystoreValue mksValue, String alias, char[] password) throws
             RepositoryException {
        KeyStoreValue ksValue = (KeyStoreValue) mksValue;
        if (null == ksValue.getKeystore()) {

            ksValue.setKeystore(loadJavaKeyStore(ksValue.getPath(), ksValue.getStoreFormat(), ksValue.getPassword()));
        }

        PrivateKey privateKey;
        try {
            privateKey = (PrivateKey) ksValue.getKeystore().getKey(alias, password);
        } catch (Exception e) {
           throw new RepositoryException("can't recover key", e);
        }
        if (privateKey != null) {
            return privateKey;
        } else {
            throw new RepositoryException("no private key found for alias "+alias);

        }
    }

    /**
     * Must be deleted because of CertificateValue constructor
     *
     * @param ks
     * @param alias
     * @return
     * @throws RepositoryException
     */
    private Certificate fillCertInfo(KeyStore ks, String alias) throws RepositoryException {
        Certificate certInfo;
        try {
            java.security.cert.Certificate certificate = ks.getCertificate(alias);
            java.security.cert.Certificate[] certs = ks.getCertificateChain(alias);

            certInfo = new Certificate(alias, (X509Certificate) certificate);
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
                for (java.security.cert.Certificate chainCert : certs) {
                    bf.append(chainCert.toString());
                }
                certInfo.setChainString(bf.toString());
                certInfo.setCertificateChain(certs);
            }

        } catch (GeneralSecurityException e) {
            throw new RepositoryException("filling certificate Info impossible", e);
        }
        return certInfo;
    }

    public void addCert(KeyStoreValue ksValue, Certificate certificate) throws RepositoryException {
        KeyStore ks = loadJavaKeyStore(ksValue.getPath(), ksValue.getStoreFormat(), ksValue.getPassword());
        KeystoreBuilder ksb = new KeystoreBuilder(ks);
        try {
            ksb.addCert(ksValue, certificate);
            ksValue.getCertificates().add(certificate);
        } catch (KeyToolsException e) {
            throw new RepositoryException(ADDCERT_ERROR, e);
        }

    }


    protected abstract StoreFormat getFormat();

}
