package com.notamethod.mkcore.test.newimpl;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import com.notamethod.mkcore.certificate.Certificate;
import com.notamethod.mkcore.common.CryptoObject;
import com.notamethod.mkcore.keystore.repository.RepositoryException;
import com.notamethod.mkcore.keystore.repository2.EntityManager;
import com.notamethod.mkcore.utils.ProviderUtil;
import com.notamethod.mkcore.test.DummyData;
import com.notamethod.mkcore.test.KSConfigTestTmp;
import com.notamethod.mkcore.test.TestUtils;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.Security;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class EnityManagerTest {

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
        EntityManager manager = null;
        try {
            manager = new EntityManager(null);
        } catch (Exception e) {
           //ok
        }

        manager = new EntityManager("c:/tmp/dummy");

        assertTrue(manager.findAll().isEmpty());
        manager = new EntityManager(fileName);
        List<CryptoObject> list = manager.findAll();
        assertTrue(list.size()==1);
        List<Certificate> list2 = manager.findAllByType(CryptoObject.Type.CERTIFICATE);
        assertTrue(list2.size()==1);
        list2 = manager.findAllByType(CryptoObject.Type.PRIVATE_KEY);
        assertTrue(list2.isEmpty());
    }

    @Test
    public void save() throws  RepositoryException {
        String fileName = System.getProperty("java.io.tmpdir")+ File.separator+"tmp.crt";
        System.out.println(fileName);
        Path f = Paths.get(fileName);
        EntityManager manager = new EntityManager(fileName);
        manager.deleteAll();
        manager.save(DummyData.newCertificate());

        manager = new EntityManager(fileName);
        assertEquals(1, manager.count());

    }

    @Test
    public void savePrivate() throws  RepositoryException {

        String fileName = System.getProperty("java.io.tmpdir")+ File.separator+"tmp.crt";
        System.out.println(fileName);
        EntityManager manager = new EntityManager(fileName);
        manager.deleteAll();
        manager.save(DummyData.newPrivateKeyValue());
        manager = new EntityManager(fileName);
        assertEquals(1, manager.count());
    }




}
