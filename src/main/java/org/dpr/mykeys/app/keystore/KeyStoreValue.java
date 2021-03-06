package org.dpr.mykeys.app.keystore;

import org.apache.commons.io.FilenameUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.dpr.mykeys.app.NodeInfo;
import org.dpr.mykeys.app.certificate.CertificateValue;

import java.io.File;
import java.security.KeyStore;
import java.util.ArrayList;
import java.util.List;

public class KeyStoreValue implements NodeInfo {

    public static final Log log = LogFactory.getLog(KeyStoreValue.class);
    private String name;
    private String path;
    private boolean isOpen = false;
    private StoreModel storeModel = StoreModel.CERTSTORE;
    private StoreFormat storeFormat;
    private StoreLocationType storeType = StoreLocationType.EXTERNAL;
    //TODO
    private boolean isTemp = false;
    //TODO
    private boolean isProtected = false;
    //TODO
    private KeyStore keystore;
    private List<CertificateValue> certificates = new ArrayList<>();
    private char[] password;

    public KeyStoreValue(String name, String path, StoreModel storeModel,
                         StoreFormat storeFormat) {
        this.name = FilenameUtils.getName(name);
        this.path = path;
        this.storeModel = storeModel;
        this.storeFormat = storeFormat;
    }

    /**
     * Defaut constructor for keystore of type JKS
     *
     * @param path full keystore's pathname
     */
    private KeyStoreValue(String path) {
        this.name = FilenameUtils.getName(path);
        this.path = path;
        this.storeModel = StoreModel.CERTSTORE;
        this.storeFormat = StoreFormat.JKS;
    }

    public KeyStoreValue(String name, String path, StoreModel storeModel,
                         StoreFormat storeFormat, StoreLocationType storeType) {
        this.name = FilenameUtils.getName(name);
        this.path = path;
        this.storeModel = storeModel;
        this.storeFormat = storeFormat;
        this.storeType = storeType;
    }

    public KeyStoreValue(File fic, StoreFormat storeFormat, char[] cs) {
        this.name = FilenameUtils.getName(fic.getPath());
        this.path = fic.getPath();
        this.storeFormat = storeFormat;
        password = cs;
    }

    public KeyStoreValue(String fic, StoreFormat storeFormat) {

        this.path = new File(fic).getPath();
        this.storeFormat = storeFormat;

    }


    @Override
    public boolean isProtected() {
        return true;
    }

    @Override
    @Deprecated
    public void open() {


    }

    public KeyStore getKeystore() {
        return keystore;
    }

    public void setKeystore(KeyStore keystore) {
        this.keystore = keystore;
    }

    /*
     * (non-Javadoc)
     *
     * @see java.lang.Object#toString()
     */
    public String toString() {
        // affichage dans le jtree
        return name;
    }

    /**
     * @return the name
     */
    public String getName() {
        return name;
    }

    /**
     * @param name the name to set
     */
    public void setName(String name) {
        this.name = name;
    }

    /**
     * @return the path
     */
    public String getPath() {
        return path;
    }

    /**
     * @param path the path to set
     */
    public void setPath(String path) {
        this.path = path;
    }

    /**
     * @return the isOpen
     */
    public boolean isOpen() {
        return isOpen;
    }

    /**
     * @return the isOpen
     */
    public boolean isCAStore() {
        return (this.storeModel.equals(StoreModel.PKISTORE) || this.storeModel.equals(StoreModel.CASTORE));
    }

    /**
     * @return the isOpen
     */
    public boolean isCertStore() {
        return (this.storeModel.equals(StoreModel.PKISTORE) || this.storeModel.equals(StoreModel.CERTSTORE));
    }
    /**
     * @param isOpen the isOpen to set
     */
    public void setOpen(boolean isOpen) {
        this.isOpen = isOpen;
    }

    /**
     * @return the password
     */
    public char[] getPassword() {
        return password;
    }

    /**
     * @param password the password to set
     */
    public void setPassword(char[] password) {
        this.password = password;
    }

    /**
     * Retourne le storeType.
     *
     * @return StoreType - le storeType.
     */
    public StoreModel getStoreModel() {
        return storeModel;
    }

    /**
     * Affecte le storeType.
     *
     * @param storeType le storeType à affecter.
     */
    public void setStoreModel(StoreModel storeType) {
        this.storeModel = storeType;
    }

    /**
     * Retourne le storeFormat.
     *
     * @return StoreFormat - le storeFormat.
     */
    public StoreFormat getStoreFormat() {
        return storeFormat;
    }

    /**
     * Affecte le storeFormat.
     *
     * @param storeFormat le storeFormat à affecter.
     */
    public void setStoreFormat(StoreFormat storeFormat) {
        this.storeFormat = storeFormat;
    }

    /**
     * @return the storeType
     */
    public StoreLocationType getStoreType() {
        return storeType;
    }

    /**
     * @param storeType the storeType to set
     */
    public void setStoreType(StoreLocationType storeType) {
        this.storeType = storeType;
    }

    @Override
    public List<CertificateValue> getChildList() {
        return certificates;
    }

    public void setChildList(List<CertificateValue> certificates) {
        this.certificates = certificates;
    }

    public List<CertificateValue> getCertificates() {
        return certificates;
    }

    public void setCertificates(List<CertificateValue> certificates) {
        this.certificates.clear();
        this.certificates.addAll(certificates);
    }
}
