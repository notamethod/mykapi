package org.dpr.mykeys.app.keystore.repository;

import org.apache.commons.io.FileUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.dpr.mykeys.app.KeyToolsException;
import org.dpr.mykeys.app.ServiceException;
import org.dpr.mykeys.app.certificate.CertificateValue;
import org.dpr.mykeys.app.keystore.*;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;
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


}
