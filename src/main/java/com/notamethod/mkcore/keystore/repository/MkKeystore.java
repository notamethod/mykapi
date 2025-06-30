package com.notamethod.mkcore.keystore.repository;

import com.notamethod.mkcore.utils.ServiceException;
import com.notamethod.mkcore.certificate.Certificate;
import com.notamethod.mkcore.keystore.KeyStoreValue;
import com.notamethod.mkcore.keystore.MKKeystoreValue;
import com.notamethod.mkcore.keystore.StoreFormat;

import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.security.PrivateKey;
import java.util.List;

public interface MkKeystore {

    static MkKeystore getInstance(StoreFormat format) {
        return
                switch (format) {
                    case PEM -> new PemKeystoreRepository();
                    case DER -> new DerKeystoreRepository();
                    case PKCS12 -> new Pkcs12KeystoreRepository();
                    default -> new JksKeystoreRepository();
                };
    }

    MKKeystoreValue create(String name, char[] password) throws RepositoryException, IOException;

    MKKeystoreValue load(String name, char[] password) throws RepositoryException;

    void removeCertificates(KeyStoreValue ksValue, List<Certificate> certificatesInfo) throws
            RepositoryException;

    void savePrivateKey(PrivateKey privateKey, String fName, char[] pass)
            throws ServiceException;

    void exportPrivateKey(PrivateKey privateKey, OutputStream os, char[] pass)
            throws ServiceException;

    void saveCertificates(KeyStoreValue ksValue, List<Certificate> certInfos);

    void save(MKKeystoreValue ksValue) throws RepositoryException;

    void update(MKKeystoreValue ksValue) throws RepositoryException;

    List<Certificate> getCertificates(MKKeystoreValue ksValue)
            throws RepositoryException;

    void addCert(KeyStoreValue ki, Certificate certificate) throws RepositoryException;

    void addCertificates(MKKeystoreValue ki, List<Certificate> certificates) throws RepositoryException;

    void save(MKKeystoreValue ksValue, SAVE_OPTION option) throws RepositoryException;

    void saveCSR(byte[] b, File f, SAVE_OPTION option) throws ServiceException;

    void saveCSR(byte[] b, OutputStream os, SAVE_OPTION option) throws ServiceException;

    PrivateKey getPrivateKey(MKKeystoreValue mksValue, String alias, char[] password) throws
            RepositoryException;

    enum SAVE_OPTION {
        REPLACE, ADD, NONE
    }
}
