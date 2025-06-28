package org.dpr.mykeys.test;

import org.dpr.mykeys.app.certificate.Certificate;
import org.dpr.mykeys.app.certificate.CertificateManager;
import org.dpr.mykeys.app.certificate.CertificateType;
import org.dpr.mykeys.app.common.PrivateKeyValue;
import org.dpr.mykeys.app.utils.ServiceException;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.util.Calendar;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.fail;

public class DummyData {

    public static Certificate newCertificate() {
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
            fail(e.getMessage());
        }
        return retValue;

    }

    public static PrivateKey newPrivateKey(){
        CertificateManager certificateManager = new CertificateManager();
        PrivateKey pk=null;
        try {
            KeyPair keyPair = certificateManager.generateKeyPair("RSA", 2048);
            pk=keyPair.getPrivate();
        } catch (ServiceException e) {
            e.printStackTrace();
        }
        return pk;
    }

    public static PrivateKeyValue newPrivateKeyValue(){
        CertificateManager certificateManager = new CertificateManager();
        PrivateKey pk=null;
        try {
            KeyPair keyPair = certificateManager.generateKeyPair("RSA", 2048);
            pk=keyPair.getPrivate();
        } catch (ServiceException e) {
            e.printStackTrace();
        }
        return new PrivateKeyValue(pk);
    }

    public static PrivateKeyValue newPrivateKeyValuepkcs8(){
        CertificateManager certificateManager = new CertificateManager();
        PrivateKey pk=null;
        try {
            KeyPair keyPair = certificateManager.generateKeyPair("RSA", 2048);
            pk=keyPair.getPrivate();
        } catch (ServiceException e) {
            throw new RuntimeException(e);
        }

        PrivateKeyValue pkv = new PrivateKeyValue(pk);
        pkv.setEnvelop("PKCS8");
        return pkv;
    }

    public static PrivateKeyValue BigKeypair(int size){
        CertificateManager certificateManager = new CertificateManager();
        PrivateKey pk=null;
        try {
            KeyPair keyPair = certificateManager.generateKeyPair("RSA", size);
            pk=keyPair.getPrivate();
        } catch (ServiceException e) {
            e.printStackTrace();
        }
        return new PrivateKeyValue(pk);
    }
}
