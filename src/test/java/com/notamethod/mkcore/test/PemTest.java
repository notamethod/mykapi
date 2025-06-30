package com.notamethod.mkcore.test;



import com.notamethod.mkcore.keystore.MKKeystoreValue;
import com.notamethod.mkcore.keystore.StoreFormat;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import com.notamethod.mkcore.certificate.CertificateManager;
import com.notamethod.mkcore.keystore.repository.MkKeystore;
import com.notamethod.mkcore.keystore.repository.PemKeystoreRepository;
import com.notamethod.mkcore.keystore.repository.RepositoryException;
import com.notamethod.mkcore.utils.ProviderUtil;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.Security;


public class PemTest {

    private final static Logger log = LogManager.getLogger(PemTest.class);

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
