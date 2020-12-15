package org.dpr.mykeys.app.keystore.repository2;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.dpr.mykeys.app.certificate.Certificate;
import org.dpr.mykeys.app.keystore.StoreFormat;
import org.dpr.mykeys.app.keystore.repository.RepositoryException;
import org.jetbrains.annotations.NotNull;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

public class JKSRepository extends AbstractCryptoRepository implements CryptoRepository {
    private static final Log log = LogFactory.getLog(JKSRepository.class);

    private Path file;
    private String state = "";
    private char[] pass;

    public JKSRepository(@NotNull Path file) throws RepositoryException {
        this.file = file;
        pass=null;
        init();
    }

    private void init() throws RepositoryException {
        if (!Files.exists(file)) {
            state = "new";
            return;
        }
        KeyStore ks = loadJavaKeyStore(StoreFormat.JKS, pass);

        Enumeration<String> enumKs;
        try {
            enumKs = ks.aliases();
            if (enumKs != null && enumKs.hasMoreElements()) {

                while (enumKs.hasMoreElements()) {
                    String alias = enumKs.nextElement();

                    Certificate certInfo = fillCertInfo(ks, alias);
                    cryptoObjects.add(certInfo);
                }
            }
        } catch (KeyStoreException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

    }
    /**
     * @param format
     * @param pwd
     * @return
     * @throws RepositoryException
     */
    KeyStore loadJavaKeyStore(StoreFormat format, char[] pwd) throws RepositoryException {
        String type = StoreFormat.getValue(format);
        KeyStore ks;
        try {
            try {
                ks = KeyStore.getInstance(type, "BC");
            } catch (Exception e) {
                ks = KeyStore.getInstance(type);
            }

            // get user password and file input stream
            try(InputStream is = Files.newInputStream(file)){
                ks.load(is, pwd);
            }


        } catch (KeyStoreException e) {
            throw new RepositoryException("Fail to load:" + file.getFileName(), e);
        } catch (FileNotFoundException e) {
            throw new RepositoryException("File not found:" + file.getFileName() + ", " + e.getCause(), e);
        } catch (NoSuchAlgorithmException e) {
            throw new RepositoryException("Format unknown:" + file.getFileName() + ", " + e.getCause(), e);
        } catch (CertificateException | IOException e) {
            throw new RepositoryException("Fail to load:" + file.getFileName() + ", " + e.getCause(), e);
        }
        return ks;
    }

    @Override
    public void persist() throws RepositoryException {

    }

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
                certInfo.setChaineStringValue(bf.toString());
                certInfo.setCertificateChain(certs);
            }

        } catch (GeneralSecurityException e) {
            throw new RepositoryException("filling certificate Info impossible", e);
        }
        return certInfo;
    }
}
