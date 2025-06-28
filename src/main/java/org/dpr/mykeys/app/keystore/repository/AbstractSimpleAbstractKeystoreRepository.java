package org.dpr.mykeys.app.keystore.repository;



import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.dpr.mykeys.app.certificate.Certificate;
import org.dpr.mykeys.app.keystore.*;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.util.List;

public abstract class AbstractSimpleAbstractKeystoreRepository extends AbstractKeystoreRepository {

    private static final Logger log = LogManager.getLogger(AbstractSimpleAbstractKeystoreRepository.class);

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

        return new SimpleKeystoreValue(name,  format);
    }

    @Override
    public void addCertificates(MKKeystoreValue ki, List<Certificate> certificates) throws RepositoryException {
        ki.getCertificates().addAll(certificates);
        save(ki,  SAVE_OPTION.REPLACE);
    }

    @Override
    public MKKeystoreValue load(String name, char[] password) throws RepositoryException {
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
