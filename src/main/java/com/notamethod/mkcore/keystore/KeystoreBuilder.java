package com.notamethod.mkcore.keystore;



import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import com.notamethod.mkcore.StringUtils;
import com.notamethod.mkcore.certificate.Certificate;
import com.notamethod.mkcore.utils.CertificateUtils;

import java.io.*;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.List;

public class KeystoreBuilder {


    public static final Logger log = LogManager.getLogger(KeystoreBuilder.class);
    private final KeyStore keystore;

    public KeystoreBuilder(KeyStore keystore) {
        super();
        this.keystore = keystore;
    }

    public KeystoreBuilder(StoreFormat format) throws KeyStoreException {
        super();
        this.keystore = KeyStore.getInstance(format.toString());
    }

    /**
     * Create a keystore of type 'ksType' with filename 'name'
     *
     * @param name
     * @param password
     * @throws IOException
     * @throws CertificateException
     * @throws NoSuchAlgorithmException
     * @throws KeyStoreException
     * @throws Exception
     *  @Deprecated replace with MKkeystore create
     */
    @Deprecated
    public KeystoreBuilder create(String name, char[] password) throws NoSuchAlgorithmException, CertificateException, IOException, KeyStoreException {
        Path path = Paths.get(name);
        if (Files.exists(path)) {
            throw new IOException("File already exists " + path.toString());
        }
        keystore.load(null, password);
        OutputStream fos = new FileOutputStream(name);
        keystore.store(fos, password);
        fos.close();

        return this;

    }

    public void addCertToKeyStoreNew(KeyStoreValue ksInfo, Certificate certInfo)
            throws KeyToolsException {

        saveCertChain(keystore, certInfo);
        saveKeyStore(keystore, ksInfo);
    }

    public KeystoreBuilder addCert(KeyStoreValue ksInfo, Certificate certInfo) throws KeyToolsException {
        saveCertChain(keystore, certInfo);
        saveKeyStore(keystore, ksInfo);
        return this;
    }

    public KeystoreBuilder addCerts(KeyStoreValue ksInfo, List<Certificate> certs) throws KeyToolsException {
        for (Certificate certInfo : certs) {
            saveCertChain(keystore, certInfo);
        }
        saveKeyStore(keystore, ksInfo);
        return this;
    }

    private String saveCertChain(KeyStore keystore, Certificate certInfo) throws KeyToolsException {

        if (StringUtils.isBlank(certInfo.getAlias())) {
            BigInteger bi = CertificateUtils.randomBigInteger(30);
            certInfo.setAlias(bi.toString(16));
        }
        try {
            if (certInfo.getPrivateKey() == null) {
                keystore.setCertificateEntry(certInfo.getAlias(), certInfo.getX509Certificate());
            } else {
                java.security.cert.Certificate[] chaine = certInfo.getCertificateChain();
                if (chaine == null)
                    chaine = new java.security.cert.Certificate[]{certInfo.getX509Certificate()};
                keystore.setKeyEntry(certInfo.getAlias(), certInfo.getPrivateKey(), certInfo.getPassword(), chaine);
            }

        } catch (KeyStoreException e) {
            throw new KeyToolsException("Sauvegarde du certificat impossible:" + certInfo.getAlias(), e);

        }
        return certInfo.getAlias();

    }

    protected void saveKeyStore(KeyStore ks, KeyStoreValue ksInfo) throws KeyToolsException {
        log.debug("saveKeyStore ");
        try (OutputStream fos = new FileOutputStream(ksInfo.getPath())) {
            ks.store(fos, ksInfo.getPassword());
        } catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException e) {
            throw new KeyToolsException("Echec de sauvegarde du magasin impossible:" + ksInfo.getPath(), e);
        }
    }
}
