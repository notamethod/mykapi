package org.dpr.mykeys.app.keystore;

import org.apache.commons.io.FilenameUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.dpr.mykeys.app.NodeInfo;
import org.dpr.mykeys.app.certificate.Certificate;


import java.io.File;
import java.security.KeyStore;
import java.util.List;

public class KeyStoreValue extends SimpleKeystoreValue implements NodeInfo, MKKeystoreValue {

    public static final Log log = LogFactory.getLog(KeyStoreValue.class);
    private String name;

    private boolean isOpen = false;
    private StoreModel storeModel = StoreModel.CERTSTORE;
    private StoreLocationType storeType = StoreLocationType.EXTERNAL;
    //TODO
    private final boolean isTemp = false;
    //TODO
    private  boolean isProtected = true;



    //TODO
    private KeyStore keystore;

    private char[] password;

    public KeyStoreValue(String path, StoreFormat format) {
        super(path, format);
        checkFormat(format);
    }

    private void checkFormat(StoreFormat format) {
        switch (format) {
            case PEM:
            case DER:
                isProtected = false;
                isOpen = true;


        }
    }

    public KeyStoreValue(String name, String filePath, StoreModel storeModel,
                         StoreFormat storeFormat) {
        this(filePath, storeFormat);
        this.name = FilenameUtils.getName(name);
        this.storeModel = storeModel;
    }

    public KeyStoreValue(String name, String filePath, StoreModel storeModel,
                         StoreFormat storeFormat, StoreLocationType storeType) {

        super(filePath, storeFormat);
        this.name = FilenameUtils.getName(name);
        this.storeModel = storeModel;
        this.storeType = storeType;
    }

    public KeyStoreValue(File fic, StoreFormat storeFormat, char[] cs) {
        super("", storeFormat);
        this.name = FilenameUtils.getName(fic.getPath());
        this.path = fic.getPath();
        this.storeFormat = storeFormat;
        password = cs;
    }

    @Override
    public boolean isProtected() {
        return isProtected;
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
     * @return the isOpen
     */
    public boolean isOpen() {
        return isOpen;
    }

    /**
     * @return the isOpen
     *
     * @deprecated replace with {@link Certificate#isAcceptChildAC()}
     */
    @Deprecated
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
    public List<Certificate> getChildList() {
        return getCertificates();
    }

    public void setChildList(List<Certificate> certificates) {
        setCertificates(certificates);
    }


}
