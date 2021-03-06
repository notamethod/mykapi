package org.dpr.mykeys.app.keystore;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.dpr.mykeys.app.KeyToolsException;
import org.dpr.mykeys.app.certificate.CertificateValue;
import org.dpr.mykeys.app.utils.CertificateUtils;

import java.io.*;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.List;

public class KeystoreBuilder {


    public static final Log log = LogFactory.getLog(KeystoreBuilder.class);
    private KeyStore keystore;

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
     */
    public KeystoreBuilder create(String name, char[] password) throws NoSuchAlgorithmException, CertificateException, IOException, KeyStoreException {
        Path path = Paths.get(name);
        if (Files.exists(path)) {
            throw new IOException("File already exists " + path.toString());
        }
        keystore.load(null, password);
        OutputStream fos = new FileOutputStream(new File(name));
        keystore.store(fos, password);
        fos.close();

        return this;

    }

    public void addCertToKeyStoreNew(KeyStoreValue ksInfo, CertificateValue certInfo)
            throws KeyToolsException {

        saveCertChain(keystore, certInfo);
        saveKeyStore(keystore, ksInfo);
    }

    public KeystoreBuilder addCert(KeyStoreValue ksInfo, CertificateValue certInfo) throws KeyToolsException {
        saveCertChain(keystore, certInfo);
        saveKeyStore(keystore, ksInfo);
        return this;
    }

    public KeystoreBuilder addCerts(KeyStoreValue ksInfo, List<CertificateValue> certs) throws KeyToolsException {
        for (CertificateValue certInfo : certs) {
            saveCertChain(keystore, certInfo);
        }
        saveKeyStore(keystore, ksInfo);
        return this;
    }

    private String saveCertChain(KeyStore keystore, CertificateValue certInfo) throws KeyToolsException {

        if (StringUtils.isBlank(certInfo.getAlias())) {
            BigInteger bi = CertificateUtils.randomBigInteger(30);
            certInfo.setAlias(bi.toString(16));
        }
        try {
            // pas bonne chaine
            // X509Certificate x509Cert = (X509Certificate) cert;

            if (certInfo.getPrivateKey() == null) {
                keystore.setCertificateEntry(certInfo.getAlias(), certInfo.getCertificate());
            } else {
                Certificate[] chaine = certInfo.getCertificateChain();
                if (chaine == null)
                    chaine = new Certificate[]{certInfo.getCertificate()};
                keystore.setKeyEntry(certInfo.getAlias(), certInfo.getPrivateKey(), certInfo.getPassword(), chaine);
            }

        } catch (KeyStoreException e) {
            throw new KeyToolsException("Sauvegarde du certificat impossible:" + certInfo.getAlias(), e);

        }
        return certInfo.getAlias();

    }

    protected void saveKeyStore(KeyStore ks, KeyStoreValue ksInfo) throws KeyToolsException {
        log.debug("saveKeyStore ");
        try (OutputStream fos = new FileOutputStream(new File(ksInfo.getPath()))) {
            ks.store(fos, ksInfo.getPassword());
        } catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException e) {
            throw new KeyToolsException("Echec de sauvegarde du magasin impossible:" + ksInfo.getPath(), e);
        }
    }
}
