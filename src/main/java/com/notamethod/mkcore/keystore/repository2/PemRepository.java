package com.notamethod.mkcore.keystore.repository2;




import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.openssl.PEMException;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import com.notamethod.mkcore.common.PrivateKeyValue;
import com.notamethod.mkcore.certificate.Certificate;
import com.notamethod.mkcore.common.CryptoObject;
import com.notamethod.mkcore.keystore.PEMType;
import com.notamethod.mkcore.keystore.repository.RepositoryException;
import org.jetbrains.annotations.NotNull;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Base64;

public class PemRepository extends AbstractCryptoRepository implements CryptoRepository  {

    private static final Logger log = LogManager.getLogger(PemRepository.class);

    private Path file;
    private String state = "";

    public PemRepository(@NotNull Path file) throws RepositoryException {
        this.file = file;
        init();
    }

    private void init() throws RepositoryException {
        if (!Files.exists(file)) {
            state = "new";
            return;
        }
        try (BufferedReader buf = new BufferedReader(new InputStreamReader( Files.newInputStream(file)))) {
            PEMParser reader = new PEMParser(buf);
            Object object;
            final JcaPEMKeyConverter jcaPEMKeyConverter = new JcaPEMKeyConverter();

            while ((object = reader.readObject()) != null) {
                if (object instanceof PrivateKeyInfo) {
                    PrivateKey privateKey;
                    try {
                        PrivateKeyInfo pki = (PrivateKeyInfo) object;
                        privateKey = jcaPEMKeyConverter.getPrivateKey(pki);

                        cryptoObjects.add(new PrivateKeyValue(privateKey));
                    } catch (PEMException e) {
                        log.error("unreadable objet ", e);
                    }

                } else if (object instanceof X509CertificateHolder) {
                    X509Certificate cert;
                    try {
                        cert = new JcaX509CertificateConverter().setProvider("BC")
                                .getCertificate((X509CertificateHolder) object);
                        Certificate certificate = new Certificate(null, cert);
                        certificate.setAlias(certificate.getName());
                        cryptoObjects.add(certificate);
                    } catch (GeneralSecurityException e) {
                        log.error("unreadable objet ", e);
                        e.printStackTrace();
                    }

                }
            }
            reader.close();
        } catch (IOException e) {
            throw new RepositoryException(e);
        }
    }


    @Override
    public void persist() throws RepositoryException {
        try (OutputStream fout =  Files.newOutputStream(file)) {
            saveBytes(fout);
        } catch (Exception e) {
            throw new RepositoryException("Can't save file:", e);
        }
    }

    private void saveBytes(OutputStream os) throws IOException, RepositoryException {
        PrintWriter osw = new PrintWriter(os);
        for (CryptoObject object : cryptoObjects) {
            byte[] base64Encoded = Base64.getEncoder().encode(object.getEncoded());
            PEMType pemType;
            try {
                pemType = PEMType.valueOf(object.getType().toString());
            } catch (IllegalArgumentException e) {
                throw new RepositoryException("Type Unknown "+ object.getType(),e);
            }
            osw.println(pemType.Begin());
            String[] datas = new String(base64Encoded).split("(?<=\\G.{64})");
            for (String line : datas) {
                osw.println(line);
            }
            osw.println(pemType.End());
        }
        osw.close();
    }
}
