package org.dpr.mykeys.test;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.dpr.mykeys.app.CertificateType;
import org.dpr.mykeys.app.KeyToolsException;
import org.dpr.mykeys.app.certificate.CertificateManager;
import org.dpr.mykeys.app.certificate.Certificate;
import org.dpr.mykeys.app.keystore.KeyStoreHelper;
import org.dpr.mykeys.app.keystore.MKKeystoreValue;
import org.dpr.mykeys.app.keystore.StoreFormat;
import org.dpr.mykeys.app.keystore.repository.MkKeystore;
import org.dpr.mykeys.app.keystore.repository.RepositoryException;
import org.dpr.mykeys.app.utils.ProviderUtil;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.Security;
import java.util.Calendar;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.fail;


public class TestExportsKeystore {

    private final static Log log = LogFactory.getLog(TestExportsKeystore.class);

    private static final String AC_NAME = "mykeys root ca 2";

    @BeforeAll
    public static void init() {

        KSConfigTestTmp.initResourceBundle();

        KSConfigTestTmp.init(".myKeys");

        Security.addProvider(new BouncyCastleProvider());

        ProviderUtil.initBC();
    }


    private void delete(Path target) {
        try {
            Files.delete(target);
        } catch (IOException e) {
            //silent e.printStackTrace();
        }
    }


    private Certificate createCert() {
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
        Certificate certIssuer = new Certificate();
        CertificateManager certServ = new CertificateManager();

        Certificate retValue = null;
        try {
            retValue = certServ.generate(certModel, certModel, CertificateType.STANDARD);
        } catch (Exception e) {
            e.printStackTrace();
            log.error(e);
            fail(e.getMessage());
        }
        return retValue;
    }
    @Test
    public void testExportP12ToP12() throws RepositoryException, IOException, KeyToolsException {
        Path source = Paths.get("target/test-classes/data/p12_two_certs.p12");
        String targetName = "p12to12";
        testExport(source, targetName, StoreFormat.PKCS12, StoreFormat.PKCS12, "2345".toCharArray(), "1234".toCharArray());
    }
    @Test
    public void testExportP12ToPem() throws RepositoryException, IOException, KeyToolsException {
        Path source = Paths.get("target/test-classes/data/p12_two_certs.p12");
        String targetName = "p12topem";
        testExport(source, targetName, StoreFormat.PKCS12, StoreFormat.PEM, "2345".toCharArray(), "1234".toCharArray());
    }
    @Test
    public void testExportP12ToDer() throws RepositoryException, IOException, KeyToolsException {
        Path source = Paths.get("target/test-classes/data/p12_two_certs.p12");
        String targetName = "p12toder";
        testExport(source, targetName, StoreFormat.PKCS12, StoreFormat.DER, "2345".toCharArray(), "1234".toCharArray());
    }
    @Test
    public void testExportP12ToJks() throws RepositoryException, IOException, KeyToolsException {
        Path source = Paths.get("target/test-classes/data/p12_two_certs.p12");
        String targetName = "p12tojks";
        testExport(source, targetName, StoreFormat.PKCS12, StoreFormat.JKS, "2345".toCharArray(), "1234".toCharArray());
    }
    @Test
    public void testExportDerToJks() throws RepositoryException, IOException, KeyToolsException {
        Path source = Paths.get("target/test-classes/data/pem_two_certs.pem");
        String targetName = "dertojks";
        testExport(source, targetName, StoreFormat.DER, StoreFormat.JKS, null, "1234".toCharArray());
    }
    @Test
    public void testExportDerToPem() throws RepositoryException, IOException, KeyToolsException {
        Path source = Paths.get("target/test-classes/data/pem_two_certs.pem");
        String targetName = "dertopem";
        testExport(source, targetName, StoreFormat.DER, StoreFormat.PEM, null, "1234".toCharArray());
    }
    @Test
    public void testExportDerToP12() throws RepositoryException, IOException, KeyToolsException {
        Path source = Paths.get("target/test-classes/data/pem_two_certs.pem");
        String targetName = "dertop12";
        testExport(source, targetName, StoreFormat.DER, StoreFormat.PKCS12, null, "1234".toCharArray());
    }
    @Test
    public void testExportPemToJks() throws RepositoryException, IOException, KeyToolsException {
        Path source = Paths.get("target/test-classes/data/pem_two_certs.pem");
        String targetName = "pemtojks";
        testExport(source, targetName, StoreFormat.PEM, StoreFormat.JKS, null, "1234".toCharArray());
    }
    @Test
    public void testExportPemToDer() throws RepositoryException, IOException, KeyToolsException {
        Path source = Paths.get("target/test-classes/data/pem_two_certs.pem");
        String targetName = "pemtoder";
        testExport(source, targetName, StoreFormat.PEM, StoreFormat.DER, null, "1234".toCharArray());
    }
    @Test
    public void testExportPemToP12() throws RepositoryException, IOException, KeyToolsException {
        Path source = Paths.get("target/test-classes/data/pem_two_certs.pem");
        String targetName = "pemtop12";
        testExport(source, targetName, StoreFormat.PEM,StoreFormat.PKCS12, null, "1234".toCharArray());
    }
    @Test
    public void testExportPemToPem() throws RepositoryException, IOException, KeyToolsException {
        Path source = Paths.get("target/test-classes/data/pem_two_certs.pem");
        String targetName = "pemtop12";
        testExport(source, targetName, StoreFormat.PEM, StoreFormat.PEM,  null, "1234".toCharArray());
    }
    @Test
    public void testExportJksToPem() throws RepositoryException, IOException, KeyToolsException {
        Path source = Paths.get("target/test-classes/data/jks_two_certs.jks");
        String targetName = "jkstopem";
        testExport(source, targetName, StoreFormat.JKS, StoreFormat.PEM, "1234".toCharArray(), null);
    }
    @Test
    public void testExportJksToDer() throws RepositoryException, IOException, KeyToolsException {
        Path source = Paths.get("target/test-classes/data/jks_two_certs.jks");
        String targetName = "jkstoder";
        testExport(source, targetName, StoreFormat.JKS, StoreFormat.DER, "1234".toCharArray(), null);
    }
    @Test
    public void testExportJksToJks() throws RepositoryException, IOException, KeyToolsException {
        Path source = Paths.get("target/test-classes/data/jks_two_certs.jks");
        String targetName = "jkstojks";
        testExport(source, targetName, StoreFormat.JKS, StoreFormat.JKS, "1234".toCharArray(), "2345".toCharArray());
    }

    @Test
    public void testExportJksToP12() throws RepositoryException, IOException, KeyToolsException {
        Path source = Paths.get("target/test-classes/data/jks_two_certs.jks");
        String targetName = "jkstop12";
        testExport(source, targetName, StoreFormat.JKS, StoreFormat.PKCS12, "1234".toCharArray(), "2345".toCharArray());
    }

    private void testExport(Path source, String targetName, StoreFormat formatIn, StoreFormat formatOut , char[] passwordIn, char[] password) throws RepositoryException, IOException, KeyToolsException {
        MKKeystoreValue keyStoreValue = null;

        List<Certificate> certificates = null;

        Path target = Paths.get("target/test-classes/data/"+targetName+formatOut.getExtension());
        MkKeystore mkKeystore = MkKeystore.getInstance(formatIn);
        String fileName = source.toAbsolutePath().toString();

        keyStoreValue = mkKeystore.load(fileName, passwordIn);
        certificates = keyStoreValue.getCertificates();
        assertEquals(2, certificates.size());

        KeyStoreHelper service = new KeyStoreHelper();
        service.export(certificates, target.toAbsolutePath().toString(), formatOut, password, MkKeystore.SAVE_OPTION.REPLACE);

        //verify
        mkKeystore = MkKeystore.getInstance(formatOut);
        MKKeystoreValue out = mkKeystore.load(target.toAbsolutePath().toString(), password);
        certificates = out.getCertificates();
        assertEquals(2, certificates.size());
    }

}
