package org.dpr.mykeys.test;


import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.dpr.mykeys.app.certificate.Certificate;
import org.dpr.mykeys.app.keystore.KeyStoreValue;
import org.dpr.mykeys.app.keystore.MKKeystoreValue;
import org.dpr.mykeys.app.keystore.StoreFormat;
import org.dpr.mykeys.app.keystore.repository.MkKeystore;
import org.dpr.mykeys.app.utils.ProviderUtil;
import org.dpr.mykeys.app.utils.ServiceException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.Security;
import java.security.cert.X509Certificate;

import static java.nio.file.StandardCopyOption.REPLACE_EXISTING;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.fail;


public class TestCerts {

    private final static Logger log = LogManager.getLogger(Test.class);

    String emptyKeystore;

    private static Certificate fillCertInfo(KeyStoreValue ksInfo, KeyStore ks, String alias) throws ServiceException {

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
                String message = "chaine de certification nulle pour " + alias + " (" + certInfo.getName() + ")";
                if (certInfo.isContainsPrivateKey())
                    log.error(message);
                else
                    log.debug(message);
                // return null;
            } else {
                for (java.security.cert.Certificate chainCert : certs) {
                    bf.append(chainCert.toString());
                }
                certInfo.setChainString(bf.toString());
                certInfo.setCertificateChain(certs);
            }

        } catch (GeneralSecurityException e) {
            throw new ServiceException("filling certificate Info impossible", e);
        }
        return certInfo;


    }

    @BeforeEach
    public void setup() throws IOException {
        Path source = Paths.get("target/test-classes/data/empty.jks");
        Path target = Paths.get("target/test-classes/data/empty_work.jks");
        Files.copy(source, target, REPLACE_EXISTING);
        emptyKeystore = target.toAbsolutePath().toString();
    }



    @Test
    public void loadKS() throws ServiceException {
        // String path = "data/test01.jks";
        // KeyStoreValue ksInfo = new KeyStoreValue("aa", path,
        // StoreModel.CERTSTORE, StoreFormat.JKS);
        String path = System.getProperty("user.dir");

        URL url = TestCerts.class.getResource("/data/test01.jks");

        try {
            log.trace(url.toURI().getPath());
        } catch (URISyntaxException e2) {
            // TODO Auto-generated catch block
            log.error(e2);
            fail();
        }

        KeyStore ks = null;

        String fileName = null;
        try {
            fileName = url.toURI().getPath().substring(1);
        } catch (URISyntaxException e2) {
            log.error(e2);
            fail();
        }
        Path resourceDirectory = Paths.get("src/test/resources/data/test01.jks");
        fileName = resourceDirectory.toAbsolutePath().toString();
        MKKeystoreValue ksInfo = null;
//        KeyStoreValue ksInfo = new KeyStoreValue("aa", fileName,
//                StoreModel.CERTSTORE, StoreFormat.JKS);
        MkKeystore mkKeystore = MkKeystore.getInstance(StoreFormat.JKS);
        try {
            ksInfo = mkKeystore.load(fileName, "1234".toCharArray() );
        } catch (Exception e1) {

            log.error(e1);
            fail();
        }
        assertEquals(1, ksInfo.getCertificates().size());
    }

    @Test
    @Disabled // ignored because very slow
    public void test16k(){
        Security.addProvider(new BouncyCastleProvider());
        ProviderUtil.init("BC");//7/31
        DummyData.BigKeypair(16384);
       // DummyData.BigKeypair(8192);
    }

}
