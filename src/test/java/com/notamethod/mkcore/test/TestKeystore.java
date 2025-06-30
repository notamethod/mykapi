package com.notamethod.mkcore.test;



import com.notamethod.mkcore.keystore.*;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import com.notamethod.mkcore.certificate.CertificateType;
import com.notamethod.mkcore.utils.ServiceException;
import com.notamethod.mkcore.certificate.CertificateManager;
import com.notamethod.mkcore.certificate.Certificate;
import com.notamethod.mkcore.keystore.repository.MkKeystore;
import com.notamethod.mkcore.keystore.repository.RepositoryException;
import com.notamethod.mkcore.utils.ProviderUtil;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.*;

import static com.notamethod.mkcore.keystore.StoreFormat.PEM;
import static com.notamethod.mkcore.keystore.StoreFormat.PKCS12;
import static java.nio.file.StandardCopyOption.REPLACE_EXISTING;
import static org.junit.jupiter.api.Assertions.*;


public class TestKeystore {

    private final static Logger log = LogManager.getLogger(TestKeystore.class);

    private static final String AC_NAME = "mykeys root ca 2";

    @BeforeAll
    public static void init() {

        KSConfigTestTmp.initResourceBundle();

        KSConfigTestTmp.init(".myKeys");

        Security.addProvider(new BouncyCastleProvider());

        ProviderUtil.initBC();
    }

    @Test
    public void load_keystore__wrong_password() {
        boolean isAC = false;
        Path resourceDirectory = Paths.get("target/test-classes/data/test01.jks");
        KeyStoreHelper service = new KeyStoreHelper();

        String fileName = resourceDirectory.toAbsolutePath().toString();
        KeyStoreValue ksInfo = new KeyStoreValue("aaz", fileName,
                StoreModel.CERTSTORE, StoreFormat.JKS);
        ksInfo.setPassword("aaa".toCharArray());
        try {
            service.load(ksInfo);
            fail();
        } catch (ServiceException e) {
            //ok;

        }
    }

    @Test
    public void load_keystore_good_password() throws IOException {
        boolean isAC = false;
        Path source = Paths.get("target/test-classes/data/empty.jks");
        Path target = Paths.get("target/test-classes/data/empty_work.jks");
        Files.copy(source, target, REPLACE_EXISTING);
        KeyStoreHelper service = new KeyStoreHelper();

        String fileName = target.toAbsolutePath().toString();
        KeyStoreValue ksInfo = new KeyStoreValue("aa", fileName,
                StoreModel.CERTSTORE, StoreFormat.JKS);
        ksInfo.setPassword("111".toCharArray());
        try {
            service.load(ksInfo);
        } catch (ServiceException e) {
            fail(e);
        }
    }

    @Test
    public void change_password_works_ok() throws IOException, RepositoryException {
        boolean isAC = false;
        Path source = Paths.get("target/test-classes/data/empty.jks");
        Path target = Paths.get("target/test-classes/data/empty_work.jks");
        Files.copy(source, target, REPLACE_EXISTING);
        KeyStoreHelper service = new KeyStoreHelper();

        String fileName = target.toAbsolutePath().toString();
        KeyStoreValue ksInfo = new KeyStoreValue("aaz", fileName,
                StoreModel.CERTSTORE, StoreFormat.JKS);
        ksInfo.setPassword("111".toCharArray());
        try {
            boolean changed = service.changePassword(ksInfo, null, "bbb".toCharArray());
            assertTrue(changed);
        } catch (TamperedWithException | KeyToolsException | ServiceException e) {
            fail(e);
        }

        MkKeystore mkKeystore = MkKeystore.getInstance(StoreFormat.JKS);
        mkKeystore.load(fileName, "bbb".toCharArray() );
        try {
            boolean changed = service.changePassword(ksInfo, "bbb".toCharArray(), "ccc".toCharArray());
            assertTrue(changed);
        } catch (TamperedWithException | KeyToolsException | ServiceException e) {
            fail(e);
        }
        mkKeystore.load(fileName, "ccc".toCharArray() );
    }

    @Test
    public void save_ok() {
        String filename = "target/test-classes/data/empty.jks";
        KeyStoreHelper service = new KeyStoreHelper();


        try {
            MkKeystore mkKeystore = MkKeystore.getInstance(StoreFormat.JKS);
            MKKeystoreValue ksInfo = mkKeystore.load(filename, "111".toCharArray() );
            mkKeystore.save(ksInfo, MkKeystore.SAVE_OPTION.REPLACE);
        } catch (RepositoryException e) {
            fail(e);
        }
    }

    @Test
    public void add_cert() throws ServiceException {

        char[] pwd = "111".toCharArray();
        String filename = "target/test-classes/data/add_cert.jks";
        Path target = Paths.get(filename);

        delete(target);

        MKKeystoreValue ki = null;
        KeystoreBuilder ksBuilder;
        KeyStoreHelper service = new KeyStoreHelper();

        try {
            MkKeystore mkKeystore = MkKeystore.getInstance(StoreFormat.JKS);
            ki = mkKeystore.create(filename, "111".toCharArray());
            //ki = service.loadKeyStore(filename, StoreFormat.JKS, "111".toCharArray());
            Certificate val =  DummyData.newCertificate();
            val.setPassword(pwd);
            //ki.setPassword(pwd);

            service.addCertToKeyStore((KeyStoreValue) ki, val, "111".toCharArray(), null);
        } catch (Exception e) {

            fail(e);
        }



    }

    private void delete(Path target) {
        try {
            Files.delete(target);
        } catch (IOException e) {
            //silent e.printStackTrace();
        }
    }

    @Test
    public void create_ks_jks() {

        KeyStoreHelper service = new KeyStoreHelper();

        String filename = "target/test-classes/data/test-create_create_ks.jks";
        Path target = Paths.get(filename);
        delete(target);


        try {
            MkKeystore mkKeystore = MkKeystore.getInstance(StoreFormat.JKS);
            mkKeystore.create(filename, "111".toCharArray());
        } catch (Exception e) {
            fail(e);
        }
    }

    @Test
    public void create_ks_p12() {

        KeyStoreHelper service = new KeyStoreHelper();

        String filename = "target/test-classes/data/test-create_create_ks.p12";
        Path target = Paths.get(filename);
        delete(target);
        KeystoreBuilder ksBuilder = null;

        try {
            ksBuilder = new KeystoreBuilder(PKCS12);
        } catch (KeyStoreException e) {
            fail(e);
        }

        try {
            MkKeystore mkKeystore = MkKeystore.getInstance(PKCS12);
            mkKeystore.create(filename, "111".toCharArray());
        } catch (Exception e) {
            fail(e);
        }
    }



    @Test
    public void testCreateCert() {
        boolean isAC = false;
        Certificate certModel = new Certificate("aliastest");
        certModel.setAlgoPubKey("RSA");
        certModel.setAlgoSig("SHA1WithRSAEncryption");

        certModel.setKeyLength(1024);
        certModel.setSubjectMap("CN=toto");
        Calendar cal = Calendar.getInstance();
        cal.add(Calendar.MONTH, 1);
        certModel.setNotBefore(new Date());
        certModel.setNotAfter(cal.getTime());
        certModel.setPolicyCPS("CPO000");
        Certificate certIssuer = new Certificate();
        CertificateManager certServ = new CertificateManager();

        Certificate retValue = null;
        try {
            retValue = certServ.generate(certModel, certModel, CertificateType.STANDARD);
            System.out.println(retValue.getPolicyCPS());

            Certificate cv = new Certificate("xx", retValue.getX509Certificate());
            System.out.println(cv.getOtherParams());
        } catch (Exception e) {
            log.error(e);
            fail(e.getMessage());
        }


    }

    @Test
    public void testExport() {

        Path resourceDirectory = Paths.get("target/test-classes/data/test1.pem");
        Certificate cv = DummyData.newCertificate();
        List<Certificate> listCert = new ArrayList<>();
        listCert.add(cv);
        String fileName = resourceDirectory.toAbsolutePath().toString();
        KeyStoreHelper service = new KeyStoreHelper();
        try {
            service.export(listCert, fileName, PEM, null, MkKeystore.SAVE_OPTION.REPLACE);
        } catch (KeyToolsException e) {
            fail();
        }
        KeyStoreValue ksv = new KeyStoreValue(fileName, PEM);
        service = new KeyStoreHelper(ksv);
        boolean found = false;
        try {
            List<Certificate> certs = service.getCertificates();
            for (Certificate cert : certs) {
                if (cert.getPublicKey().equals(cv.getPublicKey())) {
                    found = true;
                    break;
                }
            }
            assertTrue(found);
        } catch (ServiceException | UnknownKeystoreTypeException e) {
            fail(e);
        }
    }

    @Test
    public void importPemToJks() throws ServiceException, KeyStoreException, IOException, RepositoryException, CertificateException, NoSuchAlgorithmException {

        char[] pwd = "111".toCharArray();
        String filename = "target/test-classes/data/my.jks";
        String filenamePem = "target/test-classes/data/pem/3cdeb3d0.pem";
      //  MKKeystoreValue ki = null;

        MkKeystore mks = MkKeystore.getInstance(PEM);
        MKKeystoreValue ksv = mks.load(filenamePem, null);

        MkKeystore jks = MkKeystore.getInstance(StoreFormat.JKS);
        MKKeystoreValue ki = emptyKeystore(filename, pwd);
//        try {
//            ki = emptyKeystore(filename, pwd);
//        } catch (Exception e) {
//            e.printStackTrace();
//            fail();
//        }
        KeyStoreHelper service = new KeyStoreHelper();
        jks.addCertificates((KeyStoreValue) ki, ksv.getCertificates());
        //service.importElements(null, (KeyStoreValue) ki, ksv, "111".toCharArray(), null);
        //ki = service.loadKeyStore(filename, StoreFormat.JKS, "111".toCharArray());
        jks = MkKeystore.getInstance(StoreFormat.JKS);
        MKKeystoreValue reloaded = jks.load(filename, pwd);
        assertEquals(1, reloaded.getCertificates().size());
    }

    @Test
    public void getCertsPem() throws RepositoryException {


        String filenamePem = "target/test-classes/data/pem/3cdeb3d0.pem";
        KeyStoreValue ki = null;

        MkKeystore mks = MkKeystore.getInstance(PEM);
        KeyStoreValue ksv = new KeyStoreValue(filenamePem, PEM);

        assertEquals(1, mks.getCertificates(ksv).size());

    }

    @Test
    public void getCertsDer() throws RepositoryException {


        String filename = "target/test-classes/data/der/3cdeb3d0x.der";
        KeyStoreValue ki = null;

        MkKeystore mks = MkKeystore.getInstance(StoreFormat.DER);
        KeyStoreValue ksv = new KeyStoreValue(filename, StoreFormat.DER);

        assertEquals( 1, mks.getCertificates(ksv).size(),"Error assert");

    }


    @Test
    public void findType() throws IOException, RepositoryException {
        Path source = TestUtils.getCopy("pem/fffpem");
        KeyStoreHelper service = new KeyStoreHelper();
        StoreFormat f = service.findKeystoreType(source.toAbsolutePath().toString());
        assertEquals(PEM, f);
    }
    @Test
    public void findTypeByContent() throws IOException, RepositoryException {
        Path source = TestUtils.getCopy("pem/fffpem");
        KeyStoreHelper service = new KeyStoreHelper();
        service.findKeystoreTypeByContent(source.toAbsolutePath().toString());
    }

    @Test
    public void findTypeByContentJks() throws IOException, RepositoryException {
        Path source = TestUtils.getCopy("guesstype/unknownjks");
        KeyStoreHelper service = new KeyStoreHelper();
        StoreFormat format=service.findKeystoreTypeByContent(source.toAbsolutePath().toString());
        assertEquals(StoreFormat.JKS, format);
    }

    @Test
    public void findTypeByContentP12() throws IOException, RepositoryException {
        Path source = TestUtils.getCopy("guesstype/unknownp12");
        KeyStoreHelper service = new KeyStoreHelper();
        StoreFormat format=service.findKeystoreTypeByContent(source.toAbsolutePath().toString());
        assertEquals(PKCS12, format);
    }

    @Test
    public void exportPrivateKey() throws IOException, RepositoryException {
       // Path source = TestUtils.getCopy("guesstype/unknownp12");
        Path source = TestUtils.getCopy("p12/onecertwthkey.p12");
        String target = "target/test-classes/data/privatekey.crt";
        File f = new File(target);
        System.out.println(f.getAbsolutePath());
        f.delete();
        MkKeystore ksP12 = MkKeystore.getInstance(PKCS12);
        MKKeystoreValue p12Value = ksP12.load(source.toAbsolutePath().toString(), "aaa".toCharArray());
        Certificate cert = p12Value.getCertificates().get(0);
        PrivateKey pk = ksP12.getPrivateKey(p12Value, cert.getAlias(), "aaa".toCharArray());
        MkKeystore ksPem = MkKeystore.getInstance(PEM);
        MKKeystoreValue pemValue = ksPem.create(target, null);
        KeyStoreHelper service = new KeyStoreHelper();

        FileOutputStream fos = new FileOutputStream(new File(target));

        try {
            service.exportPrivateKey(pk, fos, PEM, null);
            fos.close();
        } catch (KeyToolsException e) {
            throw new RepositoryException(e);
        }

    }

    private MKKeystoreValue emptyKeystore(String filename, char[] pwd) throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException, ServiceException, RepositoryException {
        Path target = Paths.get(filename);

        delete(target);

        MkKeystore mkKeystore = MkKeystore.getInstance(StoreFormat.JKS);
        return mkKeystore.create(filename, "111".toCharArray());

    }


}
