package org.dpr.mykeys.app.keystore.repository;

import org.dpr.mykeys.app.certificate.Certificate;
import org.dpr.mykeys.app.keystore.KeyStoreValue;
import org.dpr.mykeys.app.ServiceException;
import org.dpr.mykeys.app.keystore.MKKeystoreValue;
import org.dpr.mykeys.app.keystore.StoreFormat;

import java.io.File;
import java.io.OutputStream;
import java.security.PrivateKey;
import java.util.ArrayList;
import java.util.List;

public abstract class AbstractKeystoreRepository implements MkKeystore {

    StoreFormat format;

    public void removeCertificates(KeyStoreValue ksValue, List<Certificate> certificates) throws RepositoryException {
        List<Certificate> certs = getCertificates(ksValue);
        List<Certificate> certsToRemove = new ArrayList<>();
        for (Certificate cert : certs) {
            for (Certificate certificateInfo : certificates) {
                if (certificateInfo.getName().equals(cert.getName())) {
                    certsToRemove.add(cert);
                }
            }
        }
        certs.removeAll(certsToRemove);
        saveCertificates(ksValue, certs);
    }

    public void save(MKKeystoreValue ksValue) throws RepositoryException {
        save(ksValue, MkKeystore.SAVE_OPTION.NONE);
    }

    public void update(MKKeystoreValue ksValue) throws RepositoryException {
        save(ksValue, SAVE_OPTION.REPLACE);
    }

    @Override
    public void saveCSR(byte[] b, File f, SAVE_OPTION option) throws ServiceException {
        throw new ServiceException("not implemented");
    }
    @Override
    public void exportPrivateKey(PrivateKey privateKey, OutputStream os, char[] pass)
            throws ServiceException {
        throw new ServiceException("not implemented");
    }

    public void saveCSR(byte[] b, OutputStream os, SAVE_OPTION option) throws ServiceException{
        throw new ServiceException("not implemented");
    }

}
