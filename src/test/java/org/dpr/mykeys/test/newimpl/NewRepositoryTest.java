package org.dpr.mykeys.test.newimpl;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.dpr.mykeys.app.certificate.Certificate;
import org.dpr.mykeys.app.common.CryptoObject;
import org.dpr.mykeys.app.keystore.repository.RepositoryException;
import org.dpr.mykeys.app.keystore.repository2.PemRepository;
import org.dpr.mykeys.app.utils.ProviderUtil;
import org.dpr.mykeys.test.DummyData;
import org.dpr.mykeys.test.KSConfigTestTmp;
import org.dpr.mykeys.test.TestUtils;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.Security;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

public class NewRepositoryTest {

    @BeforeAll
    public static void init() {

        KSConfigTestTmp.initResourceBundle();

        KSConfigTestTmp.init(".myKeys");

        Security.addProvider(new BouncyCastleProvider());

        ProviderUtil.initBC();
    }

    @Test
    public void open() throws IOException, RepositoryException {
        Path source = TestUtils.getCopy("pem/fffpem");
        String fileName = source.toAbsolutePath().toString();
        PemRepository pem = null;
        try {
            pem = new PemRepository(null);
        } catch (Exception e) {
           //ok
        }
        pem = new PemRepository(Paths.get("c:/tmp/dumb"));
        pem.findAll();
        assertTrue(pem.findAll().isEmpty());
        pem = new PemRepository(source);
        List<CryptoObject> list = pem.findAll();
        assertTrue(list.size()==1);
        List<Certificate> list2 = pem.findAllByType(CryptoObject.Type.CERTIFICATE);
        assertTrue(list2.size()==1);
        list2 = pem.findAllByType(CryptoObject.Type.PRIVATE_KEY);
        assertTrue(list2.isEmpty());
    }

    @Test
    public void save() throws  RepositoryException {
        String fileName = System.getProperty("java.io.tmpdir")+ File.separator+"tmp.crt";
        System.out.println(fileName);
        Path f = Paths.get(fileName);
        PemRepository pem = null;

        pem = new PemRepository(f);
        pem.deleteAll();
        pem.save(DummyData.newCertificate());
        pem.persist();
        pem = new PemRepository(f);
        assertEquals(1, pem.count());

    }

    @Test
    public void savePrivate() throws  RepositoryException {

        String fileName = System.getProperty("java.io.tmpdir")+ File.separator+"tmp.crt";
        System.out.println(fileName);
        PemRepository pem = null;
        Path f = Paths.get(fileName);
        pem = new PemRepository(f);
        pem.deleteAll();
        pem.save(DummyData.newPrivateKeyValue());
        pem.persist();
        pem = new PemRepository(f);
        assertEquals(1, pem.count());
    }




}
