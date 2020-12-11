package org.dpr.mykeys.app.keystore.repository;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.dpr.mykeys.app.certificate.Certificate;
import org.dpr.mykeys.app.keystore.*;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.util.List;

public abstract class AbstractSimpleKeystoreRepository extends KeystoreRepository {

    private static final Log log = LogFactory.getLog(AbstractSimpleKeystoreRepository.class);

    public MKKeystoreValue create(String name, char[] password) throws RepositoryException, IOException {

        log.warn("password protection not supported with this format");
        Path path = Paths.get(name);
        if (Files.exists(path)) {
            throw new IOException("File already exists " + path.toString());
        }
        try {
            Files.createFile(path);
        } catch (Exception e) {
           throw new RepositoryException(e);
        }

        MKKeystoreValue keyStoreValue = new SimpleKeystoreValue(name,  format);

        return keyStoreValue;
    }

    @Override
    public void addCertificates(MKKeystoreValue ki, List<Certificate> certificates) throws RepositoryException {
        ki.getCertificates().addAll(certificates);
        save(ki,  SAVE_OPTION.REPLACE);
    }

    @Override
    public MKKeystoreValue load(String name, char[] password) throws RepositoryException, IOException {
        MKKeystoreValue keystoreValue = new SimpleKeystoreValue(name, this.format);
        keystoreValue.setCertificates(getCertificates(keystoreValue));
        keystoreValue.setLoaded(true);
        return keystoreValue;
    }

    @Override
    public PrivateKey getPrivateKey(MKKeystoreValue mksValue, String alias, char[] password) throws
            RepositoryException {
        throw new RepositoryException("not implemented");
    }
}
