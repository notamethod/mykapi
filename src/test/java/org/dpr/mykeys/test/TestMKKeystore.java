package org.dpr.mykeys.test;



import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.dpr.mykeys.app.keystore.*;
import org.dpr.mykeys.app.keystore.repository.MkKeystore;
import org.dpr.mykeys.app.utils.ProviderUtil;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.Security;

import static org.junit.jupiter.api.Assertions.*;


public class TestMKKeystore {

    private final static Logger log = LogManager.getLogger(TestMKKeystore.class);

    private static final String AC_NAME = "mykeys root ca 2";

    @BeforeAll
    public static void init() {

        KSConfigTestTmp.initResourceBundle();

        KSConfigTestTmp.init(".myKeys");

        Security.addProvider(new BouncyCastleProvider());

        ProviderUtil.initBC();
    }


    @Test
    public void testCreate() throws IOException {
        for (StoreFormat format : StoreFormat.values()){
            create(format);
        }
    }

    private void create(StoreFormat format) throws IOException {
        String fileName0 = "target/test-classes/data/test0a"+format.getExtension();
        System.out.println("creation test "+format);
        Path resourceDirectory = Paths.get(fileName0);
        Files.deleteIfExists(resourceDirectory);
        String fileName = resourceDirectory.toAbsolutePath().toString();
        MkKeystore mkKeystore = MkKeystore.getInstance(format);
        try {
            mkKeystore.create(fileName, "abc".toCharArray());
            assertTrue( Files.exists(resourceDirectory));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
