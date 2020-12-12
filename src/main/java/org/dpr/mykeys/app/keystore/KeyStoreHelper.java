package org.dpr.mykeys.app.keystore;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.dpr.mykeys.app.*;
import org.dpr.mykeys.app.certificate.CryptoObject;
import org.dpr.mykeys.app.keystore.repository.EntityAlreadyExistsException;
import org.dpr.mykeys.app.keystore.repository.MkKeystore;
import org.dpr.mykeys.app.keystore.repository.PemKeystoreRepository;
import org.dpr.mykeys.app.keystore.repository.RepositoryException;
import org.dpr.mykeys.app.utils.X509Util;
import org.dpr.mykeys.app.utils.CertificateUtils;
import org.dpr.mykeys.app.certificate.Certificate;
import org.dpr.mykeys.app.utils.ActionStatus;

import java.io.*;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.*;

import static java.util.stream.Collectors.toMap;

public class KeyStoreHelper implements StoreService<KeyStoreValue> {
    private static final Log log = LogFactory.getLog(KeyStoreHelper.class);

    public static final String MK3_SN = "D4 A0 81";
    private KeyStoreValue ksInfo;

    public KeyStoreHelper(KeyStoreValue ksInfo) {
        this.ksInfo = ksInfo;
    }

    public KeyStoreHelper() {
        super();

    }


    public void setKsInfo(KeyStoreValue ksInfo) {
        this.ksInfo = ksInfo;
    }

    public void open() throws ServiceException {


        loadKeyStore(ksInfo.getPath(), ksInfo.getStoreFormat(), ksInfo.getPassword());


    }

    public boolean changePassword(KeyStoreValue inKsInfo, char[] oldPwd, char[] newPwd) throws TamperedWithException, KeyToolsException, ServiceException {

        MkKeystore mkKeystore = MkKeystore.getInstance(inKsInfo.getStoreFormat());
        MKKeystoreValue mkKeyStoreValue = null;
        try {
            mkKeyStoreValue = mkKeystore.load(inKsInfo.getPath(), inKsInfo.getPassword());
            //ks = loadKeyStore(ksInfo.getPath(), ksInfo.getStoreFormat(), ksInfo.getPassword()).getKeystore();
        } catch (RepositoryException | IOException e) {
            throw new TamperedWithException(e);
        }
        if (!(mkKeyStoreValue instanceof KeyStoreValue)) {
            return false;
        }
        char[] currentPwd = getPassword(inKsInfo, oldPwd);
        KeyStoreValue protectedKeystoreValue = (KeyStoreValue) mkKeyStoreValue;
        KeyStore ks = protectedKeystoreValue.getKeystore();
        Enumeration<String> enumKs;
        try {
            enumKs = ks.aliases();
            if (enumKs != null && enumKs.hasMoreElements()) {

                while (enumKs.hasMoreElements()) {
                    String alias = enumKs.nextElement();
                    if (ks.isKeyEntry(alias)) {
                        try {
                            PrivateKey pk = (PrivateKey) ks.getKey(alias, currentPwd);
                            ks.setKeyEntry(alias, pk, newPwd, ks.getCertificateChain(alias));
                        } catch (NoSuchAlgorithmException | UnrecoverableKeyException e) {
                            throw new ServiceException(e);
                        }

                    }
                }
            }
        } catch (KeyStoreException e) {
            throw new ServiceException(e);
        }

        inKsInfo.setPassword(newPwd);
        // TODO: create save file
        saveKeyStore(ks, inKsInfo.getPath(), newPwd);
        return true;
    }

    private char[] getPassword(KeyStoreValue inKsInfo, char[] password) throws PasswordNotFoundException {
        if (inKsInfo.getPassword() != null)
            return inKsInfo.getPassword();
        if (password != null)
            return password;
        throw new PasswordNotFoundException(inKsInfo.getPath());
    }

    @Deprecated
    public void saveKeyStore(KeyStore ks, String path, char[] password) throws KeyToolsException {

        try {
            OutputStream fos = new FileOutputStream(new File(path));
            ks.store(fos, password);
            fos.close();
        } catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException e) {
            throw new KeyToolsException("Echec de sauvegarde du magasin impossible:" + ksInfo.getPath(), e);
        }
    }

    private void importX509CertFromP12(String alias, KeyStoreValue ksin, char[] pwd)
            throws KeyToolsException, GeneralSecurityException, ServiceException {
        //TODO: use alias to get only one certificate
        //FIXME: but need to import all certitiftcates
        //TODO; check if alias exists in output ks
        KeyStore ks = load(ksin);

        String aliasOri = null;
        Enumeration<String> enumKs = ks.aliases();
        while (enumKs.hasMoreElements()) {
            aliasOri = enumKs.nextElement();
        }
        if (alias == null) {
            alias = aliasOri;
        }
        java.security.cert.Certificate cert = ks.getCertificate(aliasOri);
        Certificate certInfo = new Certificate(alias, (X509Certificate) cert, ksin.getPassword());

        certInfo.setCertificateChain(ks.getCertificateChain(aliasOri));
        certInfo.setPrivateKey((PrivateKey) ks.getKey(aliasOri, ksin.getPassword()));

        KeystoreBuilder ksBuilder = new KeystoreBuilder(load(ksInfo));
        ksBuilder.addCertToKeyStoreNew(ksInfo, certInfo);
    }

    public ActionStatus importCertificates(KeyStoreValue ksin, char[] newPwd)
            throws ServiceException {
        ksin.setStoreFormat(KeystoreUtils.findKeystoreType(ksin.getPath()));
        if (ksin.getPassword() == null && (StoreFormat.JKS.equals(ksin.getStoreFormat()) || StoreFormat.PKCS12.equals(ksin.getStoreFormat()))) {
            return ActionStatus.ASK_PASSWORD;
        }
        importX509CertToJks(null, ksin, newPwd);
        return null;

    }


    /**
     * @param ksName
     * @param format
     * @param pwd
     * @return
     * @throws ServiceException
     */

    private KeyStore getKeystore(String ksName, StoreFormat format, char[] pwd) throws ServiceException {
        return loadKeyStore(ksName, format, pwd).getKeystore();
    }

    public List<CryptoObject> getElements(MKKeystoreValue mkKeystoreValue) throws ServiceException {
        List<CryptoObject> certs = new ArrayList<>();

        if (mkKeystoreValue instanceof KeyStoreValue && ((KeyStoreValue) mkKeystoreValue).getPassword() == null && mkKeystoreValue.getStoreFormat().equals(StoreFormat.PKCS12)) {
            return certs;
        }
        if (mkKeystoreValue.getStoreFormat().equals(StoreFormat.UNKNOWN)) {
            mkKeystoreValue.setStoreFormat(findKeystoreType(ksInfo.getPath()));
        }
        MkKeystore mks = MkKeystore.getInstance(ksInfo.getStoreFormat());
        if (!mkKeystoreValue.isLoaded()) {
            try {
                mkKeystoreValue =  mks.load(mkKeystoreValue.getPath(), null);
            } catch (IOException e) {
                //throw new RepositoryException(e);
            } catch (RepositoryException e) {
                e.printStackTrace();
            }
        }

        certs = mkKeystoreValue.getElements();
        return certs;

    }

    public List<Certificate> getCertificates(MKKeystoreValue mkKeystoreValue) throws ServiceException {
        List<Certificate> certs = new ArrayList<>();

        if (mkKeystoreValue instanceof KeyStoreValue && ((KeyStoreValue) mkKeystoreValue).getPassword() == null && mkKeystoreValue.getStoreFormat().equals(StoreFormat.PKCS12)) {
            return certs;
        }
        if (mkKeystoreValue.getStoreFormat().equals(StoreFormat.UNKNOWN))
            mkKeystoreValue.setStoreFormat(findKeystoreType(ksInfo.getPath()));

        MkKeystore mks = MkKeystore.getInstance(ksInfo.getStoreFormat());
        if (!mkKeystoreValue.isLoaded()) {
            try {
                mkKeystoreValue =  mks.load(mkKeystoreValue.getPath(), null);
            } catch (IOException e) {
                //throw new RepositoryException(e);
            } catch (RepositoryException e) {
                e.printStackTrace();
            }
        }

        try {
            certs = mks.getCertificates(ksInfo);
            return certs;

        } catch (RepositoryException e) {
            throw new ServiceException(e);
        }
    }

    @Deprecated
    public List<Certificate> getCertificates() throws ServiceException {
        List<Certificate> certs = new ArrayList<>();

        if (ksInfo.getPassword() == null && ksInfo.getStoreFormat().equals(StoreFormat.PKCS12)) {
            return certs;
        }
        if (ksInfo.getStoreFormat().equals(StoreFormat.UNKNOWN))
            ksInfo.setStoreFormat(KeystoreUtils.findKeystoreType(ksInfo.getPath()));

        MkKeystore mks = MkKeystore.getInstance(ksInfo.getStoreFormat());

        try {
            certs = mks.getCertificates(ksInfo);
            return certs;

        } catch (RepositoryException e) {
            throw new ServiceException(e);
        }

    }

    public List<Certificate> getCertificatesForUser(KeyStoreValue ki) throws ServiceException {
        List<Certificate> certs = new ArrayList<>();

        if (ki.getPassword() == null && ki.getStoreFormat().equals(StoreFormat.PKCS12)) {
            return certs;
        }

        MkKeystore mks = MkKeystore.getInstance(ki.getStoreFormat());
        try {
            return mks.getCertificates(ki);
        } catch (RepositoryException e) {
            throw new ServiceException(e);
        }
    }

    /*
     * (non-Javadoc)
     *
     * @see org.dpr.mykeys.ihm.keystore.StoreService#getChildList()
     */
    @Override
    public List<Certificate> getChildList() throws ServiceException {

        List<Certificate> certs;
        certs = getCertificates();
        log.debug("get child list" + certs.size());
        return certs;
    }

    public List<CryptoObject> getChildList(MKKeystoreValue mkKeystoreValue) throws ServiceException {

        List<CryptoObject> certs;
        certs = getElements(mkKeystoreValue);
        log.debug("get child list" + certs.size());
        return certs;
    }

    /**
     * @param alias
     * @param value
     * @param charArray
     * @throws ServiceException
     * @deprecated use importX509CertToJks(String alias, KeyStoreValue ksIn, KeyStoreValue value, char[] pwdSource, char[] charArray)
     */
    @Deprecated
    public void importX509CertToJks(String alias, KeyStoreValue value, char[] charArray)
            throws ServiceException {
        importX509CertToJks(alias, ksInfo, value, ksInfo.getPassword(), charArray);
    }

    public void importX509CertToJks(String alias, KeyStoreValue target, KeyStoreValue source, char[] pwdSource, char[] charArray)
            throws ServiceException {


        MkKeystore mksSource = MkKeystore.getInstance(source.getStoreFormat());
        MkKeystore mksTarget = MkKeystore.getInstance(target.getStoreFormat());
        StoreFormat storeFormat = source.getStoreFormat();

        if (storeFormat == null || StoreFormat.PKCS12.equals(storeFormat)) {
            try {
                MKKeystoreValue sourceIn = mksSource.load(source.getPath(), pwdSource);

                mksTarget.addCertificates(target, mksSource.getCertificates(sourceIn));

            } catch (RepositoryException | IOException e) {
                // TODO Auto-generated catch block
                throw new ServiceException(e);
            }

        } else if (StoreFormat.JKS.equals(storeFormat)) {
            try {
                importX509CertFromJKS(alias, source, charArray);
            } catch (GeneralSecurityException e) {
                throw new ServiceException(e);
            }

        } else if (StoreFormat.DER.equals(storeFormat) || StoreFormat.PEM.equals(storeFormat)) {

            List<Certificate> certs = null;
            try {
                certs = mksSource.getCertificates(source);
                target.setPassword(pwdSource);
                mksTarget.load(target.getPath(), pwdSource);
                mksTarget.addCertificates(target, certs);
            } catch (RepositoryException | IOException e) {
                throw new ServiceException(e);
            }

        }
    }

    public void importElements(MKKeystoreValue source, MKKeystoreValue target)
            throws ServiceException {
        importElements(source, target, null);
    }

    public void importElements(MKKeystoreValue source, MKKeystoreValue target, char[] pwdSource)
            throws ServiceException {


        MkKeystore mksSource = MkKeystore.getInstance(source.getStoreFormat());
        MkKeystore mksTarget = MkKeystore.getInstance(target.getStoreFormat());

        try {
            if (!source.isLoaded() && null != pwdSource)
                source = mksSource.load(source.getPath(), pwdSource);
            else if (!source.isLoaded() && null == pwdSource)
                throw new ServiceException("keystore not loaded");

            mksTarget.addCertificates(target, mksSource.getCertificates(source));

        } catch (RepositoryException | IOException e) {
            // TODO Auto-generated catch block
            throw new ServiceException(e);
        }

    }


    public void importX509CertFromJKS(String alias0, KeyStoreValue value, char[] charArray)
            throws ServiceException, GeneralSecurityException {
        List<Certificate> certs = new ArrayList<>();

        KeyStore ks = load(value);

        Enumeration<String> enumKs;
        try {
            enumKs = ks.aliases();
            if (enumKs != null) {

                while (enumKs.hasMoreElements()) {
                    String alias = enumKs.nextElement();

                    java.security.cert.Certificate cert = ks.getCertificate(alias);
                    Certificate certInfo = new Certificate(alias, (X509Certificate) cert, value.getPassword());

                    certInfo.setCertificateChain(ks.getCertificateChain(alias));
                    certInfo.setPrivateKey((PrivateKey) ks.getKey(alias, value.getPassword()));
                    if (charArray != null)
                        certInfo.setPassword(charArray);

                    KeystoreBuilder ksBuilder = new KeystoreBuilder(load(ksInfo));
                    ksBuilder.addCert(ksInfo, certInfo);
                    certs.add(certInfo);
                }
            }
        } catch (KeyStoreException | KeyToolsException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

    }

    /**
     * Must be deleted because of CertificatValue constructor
     *
     * @param ks
     * @param alias
     * @return
     * @throws ServiceException
     */
    public Certificate fillCertInfo(KeyStore ks, String alias) throws ServiceException {
        Certificate certInfo;
        try {
            java.security.cert.Certificate certificate = ks.getCertificate(alias);
            java.security.cert.Certificate[] certs = ks.getCertificateChain(alias);

            certInfo = new Certificate(alias, (X509Certificate) certificate);
            if (ks.isKeyEntry(alias)) {
                certInfo.setContainsPrivateKey(true);

            }
            StringBuilder bf = new StringBuilder();
            if (certs == null) {
                String message = "chaine de certification nulle pour " + alias + " (" + certInfo.getName() + ")";
                if (certInfo.isContainsPrivateKey())
                    log.error(message);
                else
                    log.debug(message);
                // return null;
            } else {
                for (java.security.cert.Certificate chainCert : certs) {
                    bf.append(chainCert.toString());
                }
                certInfo.setChaineStringValue(bf.toString());
                certInfo.setCertificateChain(certs);
            }

        } catch (GeneralSecurityException e) {
            throw new ServiceException("filling certificate Info impossible", e);
        }
        return certInfo;
    }


    public void exportPrivateKey(Certificate certInfo, KeyStoreValue ksInfo, char[] passwordIn, char[] passwordOut, String fName, StoreFormat format)
            throws KeyToolsException {

        try {

            PrivateKey privateKey = getPrivateKey(ksInfo, certInfo.getAlias(), passwordIn);
            KeyStoreValue ksout = new KeyStoreValue(fName, format);
            MkKeystore mks = MkKeystore.getInstance(ksout.getStoreFormat());
            mks.savePrivateKey(privateKey, fName, passwordOut);

        } catch (Exception e) {
            e.printStackTrace();
            log.error(e);
            throw new KeyToolsException("Export de la clé privée impossible:" + certInfo.getAlias(), e);
        }
    }

    public void exportPrivateKey(PrivateKey privateKey, OutputStream os, StoreFormat format, char[] passwordOut)
            throws KeyToolsException {

        try {

            MkKeystore mks = MkKeystore.getInstance(format);
            mks.exportPrivateKey(privateKey, os, passwordOut);

        } catch (Exception e) {
            e.printStackTrace();
            log.error(e);
            throw new KeyToolsException("Export de la clé privée impossible:", e);
        }
    }

    public KeyStore importStore(String path, StoreFormat storeFormat, char[] password) throws
            ServiceException {
        if (storeFormat == null)
            storeFormat = KeystoreUtils.findKeystoreType(path);
        // TODO Auto-generated method stub
        switch (storeFormat) {
            case JKS:
            case PKCS12:
                return getKeystore(path, storeFormat, password);

            default:
                loadX509Certs(path);
                return null;
        }
    }


    /**
     * @throws ServiceException
     */
    private void addCertsToKeyStore(KeyStoreValue ki, List<Certificate> certificates) throws ServiceException {

        try {
            KeyStore ks = load(ki);
            KeystoreBuilder ksb = new KeystoreBuilder(ks);

            ksb.addCerts(ki, certificates);
        } catch (KeyToolsException e) {
            throw new ServiceException(e);
        }
    }

    /**
     * @param certificate The certificate to add in keystore
     * @param password    keystore's password
     * @throws ServiceException
     */
    public void addCertToKeyStore(KeyStoreValue ki, Certificate certificate, char[] password,
                                  char[] certificatePassword) throws ServiceException {
        if (password != null)
            ki.setPassword(password);
        if (certificatePassword != null)
            certificate.setPassword(certificatePassword);
        MkKeystore mks = MkKeystore.getInstance(ki.getStoreFormat());
        try {
            mks.addCert(ki, certificate);
        } catch (RepositoryException e) {
            throw new ServiceException(e);
        }
    }

    public Certificate findCertificateAndPrivateKeyByAlias(KeyStoreValue store, String alias) throws
            ServiceException {
        if (null == store || null == alias || alias.trim().isEmpty()) {
            throw new IllegalArgumentException();
        }
        return findCertificateByAlias(store, alias, store.getPassword());
    }

    public Certificate findCertificateByAlias(KeyStoreValue store, String alias, char[] password) throws
            ServiceException {
        if (null == store || null == alias || alias.trim().isEmpty()) {
            throw new IllegalArgumentException();
        }
        Certificate certInfo;
        try {
            KeyStore ks = load(store);
            java.security.cert.Certificate certificate = ks.getCertificate(alias);
            if (certificate == null)
                return null;
            //mk3 is a special CA: let it different for now
            if (certificate instanceof X509Certificate) {
                String sn0 = X509Util.toHexString(((X509Certificate) certificate).getSerialNumber(), " ", true);
                if (MK3_SN.equals(sn0.trim())) {
                    password = store.getPassword();
                }

            }
            java.security.cert.Certificate[] certs = ks.getCertificateChain(alias);
            certInfo = new Certificate(alias, (X509Certificate) certificate);
            if (ks.isKeyEntry(alias)) {
                certInfo.setContainsPrivateKey(true);
                if (password != null)
                    certInfo.setPrivateKey((PrivateKey) ks.getKey(alias, password));

            }
            StringBuilder bf = new StringBuilder();
            if (certs == null) {
                log.error("chaine de certification nulle pour" + alias + "(" + alias + ")");
                return null;
            }
            for (java.security.cert.Certificate chainCert : certs) {
                bf.append(chainCert.toString());
            }
            certInfo.setChaineStringValue(bf.toString());
            certInfo.setCertificateChain(certs);

        } catch (GeneralSecurityException e) {
            throw new ServiceException(e);
        }
        return certInfo;
    }

    /**
     * @param ksName
     * @param format
     * @param pwd
     * @return
     * @throws KeyToolsException
     * @deprecated replace with MKKeystore
     */
    @Deprecated
    public KeyStoreValue loadKeyStore(String ksName, StoreFormat format, char[] pwd) throws ServiceException {
        // KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
        KeyStoreValue keystoreValue = new KeyStoreValue(new File(ksName), format, pwd);

        String type = StoreFormat.getValue(format);
        keystoreValue.setPassword(pwd);
        KeyStore ks;
        try {
            try {
                ks = KeyStore.getInstance(type, "BC");
            } catch (Exception e) {
                ks = KeyStore.getInstance("JKS");
            }

            // get user password and file input stream

            java.io.FileInputStream fis = new java.io.FileInputStream(ksName);
            ks.load(fis, pwd);
            fis.close();
        } catch (KeyStoreException e) {
            throw new ServiceException("Echec du chargement de:" + ksName, e);

        } catch (FileNotFoundException e) {
            throw new ServiceException("Fichier non trouvé:" + ksName + ", " + e.getCause(), e);
        } catch (NoSuchAlgorithmException e) {
            throw new ServiceException("Format inconnu:" + ksName + ", " + e.getCause(), e);
        } catch (CertificateException | IOException e) {
            throw new ServiceException("Echec du chargement de:" + ksName + ", " + e.getCause(), e);
        }
        KeyStore keystore = ks;
        keystoreValue.setKeystore(ks);
        return keystoreValue;
    }

    public KeyStore load(KeyStoreValue ksin) throws ServiceException {

        return loadKeyStore(ksin.getPath(), ksin.getStoreFormat(), ksin.getPassword()).getKeystore();
    }


    /**
     * Load a private key from a keystore
     * @param ksInfoIn
     * @param alias alias of the private key
     * @param password
     * @return
     * @throws ServiceException
     */
    public PrivateKey getPrivateKey(KeyStoreValue ksInfoIn, String alias, char[] password) throws
            ServiceException {
        MkKeystore keystore = MkKeystore.getInstance(ksInfoIn.getStoreFormat());
        PrivateKey privateKey = null;
        try {
            privateKey = keystore.getPrivateKey(ksInfoIn, alias, password);
        } catch (RepositoryException e) {
            throw new ServiceException("no private key found for " + ksInfoIn.getPath());
        }
        return privateKey;
    }


    public KeyStoreValue createKeyStoreValue(File ksFile) {
        StoreFormat format = KeystoreUtils.findKeystoreType(ksFile.getAbsolutePath());
        return new KeyStoreValue(ksFile, format, null);
    }


    public Map<String, String> getCAMapAlias(KeyStoreValue ksv) throws ServiceException {
        MkKeystore mks = MkKeystore.getInstance(ksv.getStoreFormat());
        //  Map<String, String> certsAC = new HashMap<>();
        List<Certificate> certs = null;
        try {
            certs = mks.getCertificates(ksv);
        } catch (RepositoryException e) {
            throw new ServiceException(e);
        }

        Map<String, String> certsAC = certs.stream().
                filter(cert -> CertificateType.AC.equals(cert.getType())).
                collect(
                        toMap(Certificate::getName,
                                Certificate::getAlias,
                                (oldValue, newValue) -> newValue
                        )
                );

        return certsAC;

    }

    public boolean export(List<Certificate> certInfos, String fName, StoreFormat format, char[] pwd, MkKeystore.SAVE_OPTION option) throws KeyToolsException {
        /* save the public key in a file */
        boolean exportToNewFile = true;
        try {
            KeyStoreValue ksv = new KeyStoreValue(fName, format);
            if (pwd != null)
                ksv.setPassword(pwd);
            ksv.setCertificates(certInfos);
            MkKeystore mks = MkKeystore.getInstance(format);
            mks.save(ksv, option);

        } catch (EntityAlreadyExistsException e) {

            log.warn(e);
            return false;

        } catch (Exception e) {

            throw new KeyToolsException("Can't save file:", e);
        }
        return exportToNewFile;
    }

    private List<Certificate> loadX509Certs(String fileName) {
        List<Certificate> certsRetour = new ArrayList<>();


        try (InputStream is = new FileInputStream(new File(fileName))) {
            Set<X509Certificate> certs = CertificateUtils.loadX509Certs(is);
            for (X509Certificate cert : certs) {
                Certificate certInfo = new Certificate(null, cert);
                certsRetour.add(certInfo);
            }

        } catch (GeneralSecurityException | IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        return certsRetour;

    }

    public StoreFormat findKeystoreType(String filename) {
        StoreFormat format = KeystoreUtils.findKeystoreTypeByExtension(filename);
        if (StoreFormat.UNKNOWN.equals(format)){
            format= findKeystoreTypeByContent(filename);
        }
        return format;
    }
    public StoreFormat findKeystoreTypeByContent(String filename) {
        log.debug("finding type of file...");
        MkKeystore mkKeystore = MkKeystore.getInstance(StoreFormat.JKS);
        try {
            mkKeystore.load(filename, "".toCharArray());
        } catch (RepositoryException e) {
            if (NestedExceptionUtils.getMostSpecificCause(e) instanceof UnrecoverableKeyException
                    && e.getMessage().contains("Password verification failed")) {
                System.out.println("key");
                return StoreFormat.JKS;
            }
        } catch (IOException e) {

        }
        mkKeystore = MkKeystore.getInstance(StoreFormat.PKCS12);
        try {
            mkKeystore.load(filename, "".toCharArray());
        } catch (RepositoryException e) {
            Throwable rootException = NestedExceptionUtils.getMostSpecificCause(e);
            if (rootException instanceof IOException
                    && rootException.getMessage().contains("wrong password") && rootException.getMessage().contains("PKCS12")) {
                return StoreFormat.PKCS12;
            }
        } catch (IOException e) {

        }
        mkKeystore = MkKeystore.getInstance(StoreFormat.PEM);
        try {
           MKKeystoreValue storeValue= mkKeystore.load(filename, "".toCharArray());
           List<CryptoObject> objects =  ((PemKeystoreRepository) mkKeystore).getElements(storeValue);
            if (objects != null && !objects.isEmpty())
                return StoreFormat.PEM;
        } catch (RepositoryException e) {
            e.printStackTrace();

        } catch (IOException e) {

        }
        return StoreFormat.UNKNOWN;
    }
}
