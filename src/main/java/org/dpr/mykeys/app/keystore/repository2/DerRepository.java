package org.dpr.mykeys.app.keystore.repository2;



import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.dpr.mykeys.app.certificate.Certificate;
import org.dpr.mykeys.app.keystore.repository.RepositoryException;
import org.jetbrains.annotations.NotNull;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.*;

public class DerRepository extends AbstractCryptoRepository implements CryptoRepository  {

    private static final Logger log = LogManager.getLogger(DerRepository.class);

    private Path file;
    private String state = "";

    public DerRepository(@NotNull Path file) throws RepositoryException {
        this.file = file;
        init();
    }
    private void init() throws RepositoryException {
        if (!Files.exists(file)) {
            state = "new";
            return;
        }

        //  InputStream is = null;
        try (InputStream is = Files.newInputStream(file)) {
            CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");

            //TODO: manage der private keys

            // loading certificates
            Collection<X509Certificate> certs = (Collection<X509Certificate>) cf.generateCertificates(is);
            for (X509Certificate cert : certs) {
                Certificate certificate = new Certificate(null, cert);
                cryptoObjects.add(certificate);
            }

        } catch (GeneralSecurityException | IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
    }

    @Override
    public void persist() throws RepositoryException {

    }
}
