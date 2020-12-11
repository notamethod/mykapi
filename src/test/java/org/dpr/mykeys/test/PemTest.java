package org.dpr.mykeys.test;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.dpr.mykeys.app.certificate.CertificateManager;
import org.dpr.mykeys.app.keystore.*;
import org.dpr.mykeys.app.keystore.repository.MkKeystore;
import org.dpr.mykeys.app.keystore.repository.PemKeystoreRepository;
import org.dpr.mykeys.app.keystore.repository.RepositoryException;
import org.dpr.mykeys.app.utils.ProviderUtil;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.Security;


public class PemTest {

    private final static Log log = LogFactory.getLog(PemTest.class);

    private static final String AC_NAME = "mykeys root ca 2";

    @BeforeAll
    public static void init() {

        KSConfigTestTmp.initResourceBundle();

        KSConfigTestTmp.init(".myKeys");

        Security.addProvider(new BouncyCastleProvider());

        ProviderUtil.initBC();
    }

    @Test
    public void open_cert() throws IOException, RepositoryException {
        Path source = Paths.get("target/test-classes/data/pem/certificate.pem");
        String fileName = source.toAbsolutePath().toString();
        CertificateManager certServ = new CertificateManager();
        MkKeystore mks = MkKeystore.getInstance(StoreFormat.PEM);
        MKKeystoreValue mkKeystoreValue = mks.load(fileName, null);
        System.out.println(mkKeystoreValue.getCertificates());
    }

    @Test
    public void open_unknowncert() throws IOException, RepositoryException {
        Path source = TestUtils.getCopy("pem/fffpem");
        String fileName = source.toAbsolutePath().toString();
        CertificateManager certServ = new CertificateManager();
        MkKeystore mks = MkKeystore.getInstance(StoreFormat.PEM);
        MKKeystoreValue mkKeystoreValue = mks.load(fileName, null);
        System.out.println(mkKeystoreValue.getCertificates());
    }



    @Test
    public void open_private() throws IOException, RepositoryException {
        Path source = Paths.get("target/test-classes/data/pem/private_pkcs8.pem");
        String fileName = source.toAbsolutePath().toString();
        CertificateManager certServ = new CertificateManager();
        MkKeystore mks = MkKeystore.getInstance(StoreFormat.PEM);
        MKKeystoreValue mkKeystoreValue = mks.load(fileName, null);
        if (mks instanceof PemKeystoreRepository)
            ((PemKeystoreRepository) mks).getElements(mkKeystoreValue);
    }

    @Test
    public void open_multi() throws IOException, RepositoryException {
        Path source = Paths.get("target/test-classes/data/pem/multi.pem");
        String fileName = source.toAbsolutePath().toString();
        CertificateManager certServ = new CertificateManager();
        MkKeystore mks = MkKeystore.getInstance(StoreFormat.PEM);
        MKKeystoreValue mkKeystoreValue = mks.load(fileName, null);
        System.out.println(mkKeystoreValue.getCertificates());
        System.out.println(mkKeystoreValue.getElements().size());
    }
}
