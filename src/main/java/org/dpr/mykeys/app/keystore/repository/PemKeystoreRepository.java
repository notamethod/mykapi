package org.dpr.mykeys.app.keystore.repository;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.openssl.PEMException;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.openssl.jcajce.JcaPKCS8Generator;
import org.bouncycastle.util.io.pem.PemGenerationException;
import org.bouncycastle.util.io.pem.PemObject;
import org.dpr.mykeys.app.certificate.Certificate;
import org.dpr.mykeys.app.keystore.*;
import org.dpr.mykeys.app.ServiceException;

import java.io.*;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class PemKeystoreRepository extends AbstractSimpleKeystoreRepository {


    private static final Log log = LogFactory.getLog(PemKeystoreRepository.class);

    private Map<String, Object> elements = new HashMap<>();


    public PemKeystoreRepository() {
        this.format = StoreFormat.PEM;
    }


    public List<Certificate> getCertificates(MKKeystoreValue ksValue)
            throws RepositoryException {
        if (ksValue.getCertificates() != null && !ksValue.getCertificates().isEmpty())
            return ksValue.getCertificates();
        else {
            SimpleKeystoreValue simpleKeystoreValue = (SimpleKeystoreValue) ksValue;
            if (!simpleKeystoreValue.isLoaded()) {
                try {
                    simpleKeystoreValue = (SimpleKeystoreValue) load(simpleKeystoreValue.getPath(), null);
                } catch (IOException e) {
                    throw new RepositoryException(e);
                }
            }
            List<Certificate> certs = new ArrayList<>();
            for (Object object : simpleKeystoreValue.getElements()) {
                System.out.println(object.getClass().getName());
                 if (object instanceof Certificate){
                    certs.add((Certificate) object);
                }

            }


            ksValue.setCertificates(certs); //sure ?
            return certs;
        }
    }

    public List<PrivateKey> getPrivateKeys(MKKeystoreValue ksValue)
            throws RepositoryException {

        SimpleKeystoreValue simpleKeystoreValue = (SimpleKeystoreValue) ksValue;
        if (!simpleKeystoreValue.isLoaded()) {
            try {
                simpleKeystoreValue = (SimpleKeystoreValue) load(simpleKeystoreValue.getPath(), null);
            } catch (IOException e) {
                throw new RepositoryException(e);
            }
        }
        List<PrivateKey> keys = new ArrayList<>();
        final JcaPEMKeyConverter jcaPEMKeyConverter = new JcaPEMKeyConverter();
        for (Object object : simpleKeystoreValue.getElements()) {
            if (object instanceof PrivateKeyInfo) {
                PrivateKey privateKey = null;
                try {
                    PrivateKeyInfo pki = (PrivateKeyInfo) object;
                    privateKey = jcaPEMKeyConverter.getPrivateKey(pki);
                    String algOid = pki.getPrivateKeyAlgorithm().getAlgorithm().getId();
                    //privateKey.get
                    keys.add(privateKey);
                } catch (PEMException e) {
                    log.error("unreadable objet ", e);
                }

            }

        }

        //ksValue.setCertificates(certs); //sure ?
        return keys;

    }

    public List<Object> getElements(MKKeystoreValue ksValue)
            throws RepositoryException {

        List<Object> elements = new ArrayList<>();
        try (BufferedReader buf = new BufferedReader(new InputStreamReader(new FileInputStream(ksValue.getPath())))) {
            PEMParser reader = new PEMParser(buf);
            Object object;
            final JcaPEMKeyConverter jcaPEMKeyConverter = new JcaPEMKeyConverter();

            while ((object = reader.readObject()) != null) {
                if (object instanceof PrivateKeyInfo) {
                    PrivateKey privateKey = null;
                    try {
                        PrivateKeyInfo pki = (PrivateKeyInfo) object;
                        privateKey = jcaPEMKeyConverter.getPrivateKey(pki);
                        String algOid = pki.getPrivateKeyAlgorithm().getAlgorithm().getId();
                        //privateKey.get
                        elements.add(privateKey);
                    } catch (PEMException e) {
                        log.error("unreadable objet ", e);
                    }

                } else if (object instanceof X509CertificateHolder) {
                    X509Certificate cert = null;
                    try {
                        cert = new JcaX509CertificateConverter().setProvider("BC")
                                .getCertificate((X509CertificateHolder) object);
                        Certificate certificate = new Certificate(null, cert);
                        certificate.setAlias(certificate.getName());
                        elements.add(certificate);
                    } catch (GeneralSecurityException e) {
                        log.error("unreadable objet ", e);
                        e.printStackTrace();
                    }

                }
            }
            reader.close();
            log.info("xxx ksvalue no more filled");
            //ksValue.setCertificates(certs);


        } catch (IOException e) {
            throw new RepositoryException(e);
        }

        return elements;

    }

    public List<Object> getElementsObjects(MKKeystoreValue ksValue)
            throws RepositoryException {

        List<Object> elements = new ArrayList<>();
        try (BufferedReader buf = new BufferedReader(new InputStreamReader(new FileInputStream(ksValue.getPath())))) {
            PEMParser reader = new PEMParser(buf);
            Object object;
            final JcaPEMKeyConverter jcaPEMKeyConverter = new JcaPEMKeyConverter();
            List<PrivateKey> keys = new ArrayList<>();
            while ((object = reader.readObject()) != null) {
                elements.add(object);
            }
            reader.close();
        } catch (IOException e) {
            throw new RepositoryException(e);
        }

        return elements;

    }

    @Override
    public void addCert(KeyStoreValue ki, Certificate certificate) {

    }

    @Override
    public void save(MKKeystoreValue ksValue, SAVE_OPTION option) throws RepositoryException {
        File f = new File(ksValue.getPath());
        if (f.exists() && option.equals(SAVE_OPTION.NONE)) {
            throw new EntityAlreadyExistsException("File already exists " + f.getAbsolutePath());
        }
        /* save the public key in a file */
        try (FileOutputStream fout = new FileOutputStream(f)) {
            List<byte[]> encodedList = new ArrayList<>();
            for (Certificate certInfo : ksValue.getCertificates()) {
                encodedList.add(certInfo.getCertificate().getEncoded());
            }
            saveBytes(encodedList, fout, PEMType.CERTIFICATE);
        } catch (Exception e) {

            throw new RepositoryException("Can't save file:", e);
        }
    }


    public void savePrivateKey(PrivateKey privateKey, String fName, char[] pass)
            throws ServiceException {
        savePrivateKey(privateKey, fName);
    }

    public void savePrivateKey(PrivateKey privateKey, String fName)
            throws ServiceException {
        try (FileOutputStream f = new FileOutputStream(fName)) {
            byte[] privKey = privateKey.getEncoded();
            saveBytes(privKey, f, PEMType.PRIVATE_KEY);

        } catch (Exception e) {
            throw new ServiceException("Fail to export private key", e);
        }
    }

    public void exportPrivateKey(PrivateKey privateKey, OutputStream os, char[] pass)
            throws ServiceException {
        try {
            byte[] privKey = privateKey.getEncoded();
            saveBytes(privKey, os, PEMType.PRIVATE_KEY);

        } catch (Exception e) {
            throw new ServiceException("Fail to export private key", e);
        }
    }

    public void exportPrivateKeyBC(PrivateKey privateKey, OutputStream os, char[] pass)
            throws ServiceException {
        //unencrypted form of PKCS#8 file
        JcaPKCS8Generator gen1 = null;
        try {
            gen1 = new JcaPKCS8Generator(privateKey, null);
            PemObject obj1 = gen1.generate();
            StringWriter sw1 = new StringWriter();
            JcaPEMWriter pw = new JcaPEMWriter(sw1);
            pw.writeObject(obj1);
            pw.close();
            String pkcs8Key1 = sw1.toString();
            os.write(pkcs8Key1.getBytes());
            os.flush();
            PEMParser reader = new PEMParser(new StringReader(pkcs8Key1));
            Object obj;
            while ((obj = reader.readObject()) != null) {
                System.out.println(obj.getClass());
            }
//            //encrypted form of PKCS#8 file
//            JceOpenSSLPKCS8EncryptorBuilder encryptorBuilder = new JceOpenSSLPKCS8EncryptorBuilder(PKCS8Generator.PBE_SHA1_RC2_128);
//            encryptorBuilder.setRandom(new SecureRandom());
//            encryptorBuilder.setPasssword("abcde".toCharArray()); // password
//            OutputEncryptor encryptor = encryptorBuilder.build();
//
//            JcaPKCS8Generator gen2 = new JcaPKCS8Generator(keyPair.getPrivate(), encryptor);
//            PemObject obj2 = gen2.generate();
//            StringWriter sw2 = new StringWriter();
//            try (JcaPEMWriter pw = new JcaPEMWriter(sw2)) {
//                pw.writeObject(obj2);
//            }
//            String pkcs8Key2 = sw2.toString();
//            FileOutputStream fos2 = new FileOutputStream("D:\\privatekey-encrypted.pkcs8");
//            fos2.write(pkcs8Key2.getBytes());
//            fos2.flush();
//            fos2.close();
        } catch (PemGenerationException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }

    }


    public void saveCSR(byte[] b, File f, SAVE_OPTION option) throws ServiceException {

        try (FileOutputStream fout = new FileOutputStream(f)) {
            saveBytes(b, fout, PEMType.REQUEST);
        } catch (Exception e) {
            throw new ServiceException("Fail to export private key", e);
        }
    }

    public void saveCSR(byte[] b, OutputStream os, SAVE_OPTION option) throws ServiceException {

        try {
            saveBytes(b, os, PEMType.REQUEST);
        } catch (IOException e) {
            throw new ServiceException("Fail to export csr", e);
        }

    }

    public void saveBytes(byte[] encoded, OutputStream os, PEMType pemType) throws IOException {
        List<byte[]> encodedList = new ArrayList<>();
        encodedList.add(encoded);
        saveBytes(encodedList, os, pemType);
    }


    public void saveBytes(List<byte[]> encodedObjects, OutputStream os, PEMType pemType) throws IOException {

        PrintWriter osw = new PrintWriter(os);
        for (byte[] encoded : encodedObjects) {
            byte[] base64Encoded = Base64.encodeBase64(encoded);
            osw.println(pemType.Begin());
            String[] datas = new String(base64Encoded).split("(?<=\\G.{64})");
            for (String line : datas) {
                osw.println(line);
            }
            osw.println(pemType.End());
        }
        osw.close();
    }

    @Override
    public void saveCertificates(KeyStoreValue ksValue, List<Certificate> certInfos) {

    }

    @Override
    public MKKeystoreValue load(String name, char[] password) throws RepositoryException, IOException {
        SimpleKeystoreValue keystoreValue = new SimpleKeystoreValue(name, this.format);
        List<Object> elements = getElements(keystoreValue);
        keystoreValue.addAllElements(elements);
        keystoreValue.setLoaded(true);
        getCertificates(keystoreValue);
        return keystoreValue;
    }
}
