package com.notamethod.mkcore.test;

import com.notamethod.mkcore.keystore.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import com.notamethod.mkcore.utils.ServiceException;
import com.notamethod.mkcore.keystore.repository.MkKeystore;
import com.notamethod.mkcore.keystore.repository.RepositoryException;
import com.notamethod.mkcore.utils.ProviderUtil;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.Security;
import java.util.List;

import static com.notamethod.mkcore.keystore.StoreFormat.*;
import static java.nio.file.StandardCopyOption.REPLACE_EXISTING;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.fail;

public class TestImports {

    String emptyJks;
    @BeforeAll
    public static void init() {

        KSConfigTestTmp.initResourceBundle();

        KSConfigTestTmp.init(".myKeys");

        Security.addProvider(new BouncyCastleProvider());

        ProviderUtil.initBC();
    }
    @BeforeEach
    public void setup() throws IOException {
        Path source = Paths.get("target/test-classes/data/empty.jks");
        Path target = Paths.get("target/test-classes/data/empty_work.jks");
        Files.copy(source, target, REPLACE_EXISTING);
        emptyJks = target.toAbsolutePath().toString();
    }

    @Test
    public void ImportX509P12ToJks() {

        try {
            String typeCert = null;

            String alias = "aaa";
            String pathCert = "target/test-classes/data/aaa.p12";
            KeyStoreValue ksInfo = new KeyStoreValue("aa", emptyJks,
                    StoreModel.CERTSTORE, JKS);
            ksInfo.setPassword("111".toCharArray());
            File f = new File(pathCert);
            KeyStoreValue ksIn = new KeyStoreValue(new File(pathCert),
                    PKCS12, "aaa".toCharArray());
            KeyStoreHelper kserv = new KeyStoreHelper(ksInfo);
            kserv.importElements(ksIn, ksInfo, "aaa".toCharArray());

            KeyStoreHelper kservRet = new KeyStoreHelper(ksInfo);
            List<?> lst = kservRet.getChildList();
            assertEquals(1, lst.size());

        } catch (Exception e) {
            fail(e);


        }

    }

    @Test
    public void ImportX509JksToP12() {
        try {
            Path source = getCopy("jks_two_certs.jks");
            Path target = getCopy("p12_one_cert.p12");

            MkKeystore ksJks = MkKeystore.getInstance(JKS);
            MKKeystoreValue ksSource = ksJks.load(source.toAbsolutePath().toString(), "1234".toCharArray());
            MkKeystore ksP12 = MkKeystore.getInstance(PKCS12);
            MKKeystoreValue ksTarget = ksP12.load(target.toAbsolutePath().toString(), "aaa".toCharArray());
            System.out.println(ksTarget.getCertificates().size());
            System.out.println(ksSource.getCertificates().size());
            KeyStoreHelper kserv = new KeyStoreHelper((KeyStoreValue) ksTarget);
            kserv.importElements(ksSource, ksTarget, "aaa".toCharArray());
            ksTarget = ksP12.load(target.toAbsolutePath().toString(), "aaa".toCharArray());
            System.out.println(ksTarget.getCertificates().size());
            assertEquals(3, ksTarget.getCertificates().size());

        } catch (Exception e) {
            fail(e);


        }

    }

    @Test
    public void ImportX509PemToP12() {
        try {
            Path source = getCopy("pem_two_certs.pem");
            Path target = getCopy("p12_one_cert.p12");

            MkKeystore repositorySource = MkKeystore.getInstance(StoreFormat.PEM);
            MKKeystoreValue ksSource = repositorySource.load(source.toAbsolutePath().toString(), "1234".toCharArray());
            MkKeystore ksP12 = MkKeystore.getInstance(PKCS12);
            MKKeystoreValue ksTarget = ksP12.load(target.toAbsolutePath().toString(), "aaa".toCharArray());
            System.out.println(ksTarget.getCertificates().size());
            System.out.println(ksSource.getCertificates().size());
            KeyStoreHelper kserv = new KeyStoreHelper((KeyStoreValue) ksTarget);
            kserv.importElements(ksSource, ksTarget, "aaa".toCharArray());
            ksTarget = ksP12.load(target.toAbsolutePath().toString(), "aaa".toCharArray());
            System.out.println(ksTarget.getCertificates().size());
            assertEquals(3, ksTarget.getCertificates().size());

        } catch (Exception e) {
            fail(e);


        }

    }

    @Test
    public void ImportX509DerToP12() {
        try {
            Path source = getCopy("der_two_certs.der");
            Path target = getCopy("p12_one_cert.p12");

            MkKeystore repositorySource = MkKeystore.getInstance(DER);
            MKKeystoreValue ksSource = repositorySource.load(source.toAbsolutePath().toString(), "1234".toCharArray());
            MkKeystore ksP12 = MkKeystore.getInstance(PKCS12);
            MKKeystoreValue ksTarget = ksP12.load(target.toAbsolutePath().toString(), "aaa".toCharArray());
            System.out.println(ksSource.getCertificates().size()+" "+ksTarget.getCertificates().size());
            KeyStoreHelper kserv = new KeyStoreHelper((KeyStoreValue) ksTarget);
            kserv.importElements(ksSource, ksTarget, "aaa".toCharArray());
            ksTarget = ksP12.load(target.toAbsolutePath().toString(), "aaa".toCharArray());
            assertEquals(3, ksTarget.getCertificates().size());

        } catch (Exception e) {
            fail(e);


        }

    }

    @Test
    public void ImportX509DerToJKS() {
        try {
            Path source = getCopy("der_two_certs.der");
            Path target = getCopy("jks_two_certs.jks");

            MkKeystore repositorySource = MkKeystore.getInstance(DER);
            MKKeystoreValue ksSource = repositorySource.load(source.toAbsolutePath().toString(), "1234".toCharArray());
            MkKeystore repositoryTarget = MkKeystore.getInstance(JKS);
            MKKeystoreValue ksTarget = repositoryTarget.load(target.toAbsolutePath().toString(), "1234".toCharArray());
            System.out.println(ksSource.getCertificates().size()+" "+ksTarget.getCertificates().size());
            KeyStoreHelper kserv = new KeyStoreHelper((KeyStoreValue) ksTarget);
            kserv.importElements(ksSource, ksTarget, "1234".toCharArray());
            ksTarget = repositoryTarget.load(target.toAbsolutePath().toString(), "1234".toCharArray());
            assertEquals(4, ksTarget.getCertificates().size());

        } catch (Exception e) {
            fail(e);
        }
    }
    @Test
    public void ImportX509PemToJKS() {
        try {
            Path source = getCopy("pem_two_certs.pem");
            Path target = getCopy("jks_two_certs.jks");

            MkKeystore repositorySource = MkKeystore.getInstance(StoreFormat.PEM);
            MKKeystoreValue ksSource = repositorySource.load(source.toAbsolutePath().toString(), "1234".toCharArray());
            MkKeystore repositoryTarget = MkKeystore.getInstance(JKS);
            MKKeystoreValue ksTarget = repositoryTarget.load(target.toAbsolutePath().toString(), "1234".toCharArray());
            System.out.println(ksSource.getCertificates().size()+" "+ksTarget.getCertificates().size());
            KeyStoreHelper kserv = new KeyStoreHelper((KeyStoreValue) ksTarget);
            kserv.importElements(ksSource, ksTarget, "1234".toCharArray());
            ksTarget = repositoryTarget.load(target.toAbsolutePath().toString(), "1234".toCharArray());
            assertEquals(4, ksTarget.getCertificates().size());

        } catch (Exception e) {
            fail(e);
        }
    }

    @Test
    public void ImportX509JksToJKS() {
        try {
            Path source = getCopy("jks_one_cert.jks");
            Path target = getCopy("jks_two_certs.jks");

            MkKeystore repositorySource = MkKeystore.getInstance(JKS);
            MKKeystoreValue ksSource = repositorySource.load(source.toAbsolutePath().toString(), "1234".toCharArray());
            MkKeystore repositoryTarget = MkKeystore.getInstance(JKS);
            MKKeystoreValue ksTarget = repositoryTarget.load(target.toAbsolutePath().toString(), "1234".toCharArray());
            System.out.println(ksSource.getCertificates().size()+" "+ksTarget.getCertificates().size());
            KeyStoreHelper kserv = new KeyStoreHelper((KeyStoreValue) ksTarget);
            kserv.importElements(ksSource, ksTarget, "1234".toCharArray());
            ksTarget = repositoryTarget.load(target.toAbsolutePath().toString(), "1234".toCharArray());
            assertEquals(3, ksTarget.getCertificates().size());

        } catch (Exception e) {
            fail(e);
        }
    }

    @Test
    public void ImportX509P12ToP12FailWhenKeyExists() throws IOException, RepositoryException {

            Path target = getCopy("p12_one_cert.p12");
            Path source = getCopy("p12_one_cert.p12");
            MkKeystore repositorySource = MkKeystore.getInstance(PKCS12);
            final MKKeystoreValue ksSource = repositorySource.load(source.toAbsolutePath().toString(), "aaa".toCharArray());
            MkKeystore repositoryTarget = MkKeystore.getInstance(PKCS12);
            final MKKeystoreValue ksTarget = repositoryTarget.load(target.toAbsolutePath().toString(), "aaa".toCharArray());
            System.out.println(ksSource.getCertificates().size()+" "+ksTarget.getCertificates().size());
            KeyStoreHelper kserv = new KeyStoreHelper((KeyStoreValue) ksTarget);
            Assertions.assertThrows(ServiceException.class, () -> {
                kserv.importElements(ksSource, ksTarget, "aaa".toCharArray());
            });

    }

    @Test
    public void ImportX509P12ToDer() throws IOException, RepositoryException {
        Path target = getCopy("der_two_certs.der");
        Path source = getCopy("p12_one_cert.p12");
        int finalSize = ImportX509(source, target, PKCS12, DER, "aaa".toCharArray(),null );
        assertEquals(3, finalSize);
    }
    @Test
    public void ImportX509JksToDer() throws IOException, RepositoryException {
        Path target = getCopy("der_two_certs.der");
        Path source = getCopy("jks_one_cert.jks");
        int finalSize = ImportX509(source, target, JKS, DER, "1234".toCharArray(),null );
        assertEquals(3, finalSize);
    }
    @Test
    public void ImportX509PemToDer() throws IOException, RepositoryException {
        Path target = getCopy("der_two_certs.der");
        Path source = getCopy("pem_two_certs.pem");

        int finalSize = ImportX509(source, target, PEM, DER, "1234".toCharArray(),null );
        assertEquals(4, finalSize);
    }
    @Test
    public void ImportX509P12ToP12() throws IOException, RepositoryException {
        Path target = getCopy("p12_otherone_cert.p12");
        Path source = getCopy("p12_one_cert.p12");
        int finalSize = ImportX509(source, target, PKCS12, PKCS12, "aaa".toCharArray(),"4567".toCharArray() );
        assertEquals(2, finalSize);
    }
    public int ImportX509(Path source, Path target, StoreFormat formatSource, StoreFormat formatTarget, char[] pwdSource,char[] pwdTarget ) throws IOException, RepositoryException {

        MkKeystore repositorySource = MkKeystore.getInstance(formatSource);
        final MKKeystoreValue ksSource = repositorySource.load(source.toAbsolutePath().toString(), pwdSource);
        MkKeystore repositoryTarget = MkKeystore.getInstance(formatTarget);
        MKKeystoreValue ksTarget = repositoryTarget.load(target.toAbsolutePath().toString(), pwdTarget);
        System.out.println("source "+ksSource.getCertificates().size()+" "+"target "+ksTarget.getCertificates().size());
        ksSource.getCertificates().stream().forEach(s -> System.out.println("source "+s.getName()));
        ksTarget.getCertificates().stream().forEach(s -> System.out.println("target "+s.getName()));
        KeyStoreHelper kserv = new KeyStoreHelper();
        try {
            kserv.importElements(ksSource, ksTarget);
        } catch (ServiceException e) {
            fail(e);
        }
        ksTarget = repositoryTarget.load(target.toAbsolutePath().toString(), pwdTarget);
        return ksTarget.getCertificates().size();


    }
    private Path getCopy(String filename, String suffix) throws IOException {
        String root = "src/test/resources/data/";
        String rootCopy = "target/test-classes/data/";
        Path source = Paths.get(root + filename);
        Path target = Paths.get(rootCopy + filename+"."+suffix);
        Files.copy(source, target, REPLACE_EXISTING);
        return target;
    }

    private Path getCopy(String filename) throws IOException {
        return getCopy(filename,"work");
    }
}
