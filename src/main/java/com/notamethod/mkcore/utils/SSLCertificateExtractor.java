package com.notamethod.mkcore.utils;




import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import javax.net.ssl.*;
import java.io.*;
import java.net.Socket;
import java.net.URI;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.*;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Set;

/**
 * Class to connect to a SSL socket and analyze the certificate chain presented.  If possible, the root certificate
 * of the chain will be extracted and saved to a PEM-encoded x.509 certificate file.  Optionally, a root certificate
 * file may be specified and the SSL certificate chain will be verified against that root certificate (used to test
 * that you have the correct root certificate).
 */
public class SSLCertificateExtractor {


    public static final int EXIT_CONNECT_FAILURE = 1;
    public static final int EXIT_SSL_ERROR = 2;
    public static final int EXIT_CERT_MISMATCH = 3;
    public static final int EXIT_NO_ROOT_CERT_FOUND = 5;
    public static final int EXIT_VERIFY_CERT_NO_EXIST = 6;
    public static final int EXIT_VERIFY_CERT_LOAD_ERROR = 7;
    public static final int EXIT_WRITE_ROOT_CERT_ERROR = 8;
    public static final int EXIT_SERVER_CHAIN_ERROR = 9;

    public static final String BEGIN_CERT = "-----BEGIN CERTIFICATE-----";
    public static final String END_CERT = "-----END CERTIFICATE-----";


    private static final Logger log = LogManager.getLogger(SSLCertificateExtractor.class);
    private final String url;
    private String connectx;
    private String verifyCert;
    private Principal lastIssuer;
    private Principal lastSubject;
    private X509Certificate lastCert;
    private X509Certificate rootCert;
    private X509Certificate certToVerify;
    private final List<X509Certificate> certificateChain = new ArrayList<>();
    private int certsSent;

    public SSLCertificateExtractor(String url) {
        this.url = url;
    }

    public String run(String defaultCertificatePath, boolean getFullChaine, boolean checkValidity) throws Exception {

        URI uri = new URI(url);
        File outputFile;

        String host = uri.getHost();
        int port = uri.getPort();
        if (port < 0)
            port = 443;
        Set<TrustAnchor> anchors = getTrustAnchors();
        try {
            SSLContext ctx;
            ctx = SSLContext.getInstance("TLS");
            ctx.init(null, new TrustManager[]{new CustomTrustManager()}, null);

            printMessage("Loading Java's root certificates...");

            if (verifyCert != null) {
                printMessage("Loading your certificate from: " + verifyCert);
                File f = new File(verifyCert);
                if (!f.exists()) {
                    printMessage("ERROR: the file does not exist: " + verifyCert);
                    throw new Exception("Extraction error: " + EXIT_VERIFY_CERT_NO_EXIST);
                }
                try (InputStream in = new FileInputStream(f)) {
                    CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
                    certToVerify = (X509Certificate) certificateFactory.generateCertificate(in);
                } catch (Exception e) {
                    printMessage("ERROR: could not load certificate: " + e);
                    throw new Exception("Extraction error: " + EXIT_VERIFY_CERT_LOAD_ERROR);
                }
            }

            printMessage("Connecting to " + url);
            try (Socket s = ctx.getSocketFactory().createSocket(host, port)) {
                printMessage("Connected? " + s.isConnected());
                OutputStream os = s.getOutputStream();
                os.write("GET / HTTP/1.1\n\n".getBytes());
                os.close();
            }

            printMessage(String.format("The server sent %d certificates", certsSent));

            printMessage("The root certificate appears to be " + lastIssuer.getName());

            if (lastIssuer.equals(lastSubject)) {
                // The last certificate was self-signed.  This could either be a single self-signed cert or the root
                // cert (root CA certs are always self-signed since they're the trust anchor).
                if (certsSent == 1) {
                    printMessage("It appears this server is using a self-signed certificate");
                    rootCert = lastCert;
                    X509Certificate anchor = findAnchor(anchors, lastIssuer);
                    printMessage(String.format("NOTE: When using self-signed certificates, the application will need " +
                                    "to trust this certificate.  The Java VM running this program %s trust it.",
                            anchor == null ? "DOES NOT" : "DOES"));
                } else {
                    printMessage("It appears that the server did send us the root certificate (not typical)");
                    rootCert = lastCert;
                    X509Certificate anchor = findAnchor(anchors, lastIssuer);
                    if (anchor == null) {
                        printMessage("NOTE: your server sent the root CA cert during SSL negotiation.  However, " +
                                "this Java VM does not recognize it as trusted.  You'll need to make sure that any " +
                                "application environments install this certificate as a trusted certificate.");
                    } else {
                        // Java also has the cert... use Java's version since we trust that more.
                        rootCert = anchor;
                    }
                }
            } else {
                // Server didn't send the root CA cert.  See if Java recognizes it.
                X509Certificate anchor = findAnchor(anchors, lastIssuer);
                if (anchor == null) {
                    // Java doesn't have it... did the user give us a cert to test?
                    if (verifyCert != null) {
                        if (certToVerify.getSubjectX500Principal().equals(lastIssuer)) {
                            printMessage("  and Java doesn't have this certificate as a trusted certificate.  " +
                                    "However, the certificate you passed to verify IS the correct root certificate!");
                            rootCert = certToVerify;
                        } else {
                            printMessage("ERROR: Java doesn't have this certificate as a trusted certificate AND " +
                                    "the certificate you passed to verify does not appear to match the required " +
                                    "root certificate.");

                            printMessage(String.format("Your certificate: %s\nRequired root: %s",
                                    certToVerify.getSubjectX500Principal(), rootCert.getSubjectX500Principal()));
                            throw new Exception("Extraction error: " + EXIT_CERT_MISMATCH);
                        }
                    } else {
                        printMessage("  and Java doesn't have this certificate as a trusted certificate.  This may " +
                                "happen if you're not using a common CA (Certificate Authority) or your " +
                                "organization runs its own CA.  Please contact your security administrator and " +
                                "tell them you're looking for the root certificate for " + lastIssuer);
                        throw new Exception("Extraction error: " + EXIT_NO_ROOT_CERT_FOUND);
                    }
                } else {
                    printMessage("  the server didn't send the CA cert (normal), but Java recognizes it as trusted.");
                    if (getFullChaine)
                        certificateChain.add(anchor);
                    rootCert = anchor;
                }
            }
            if (checkValidity)
                verifyChain(certificateChain, anchors);
            // write out the root
            outputFile = new File(defaultCertificatePath, host + ".pem");
            try (FileOutputStream out = new FileOutputStream(outputFile)) {
                Base64.Encoder encoder = Base64.getMimeEncoder(64, new byte[]{0x0a});
                for (X509Certificate x509Cert : certificateChain) {
                    out.write(BEGIN_CERT.getBytes(StandardCharsets.US_ASCII));
                    out.write(0x0a);  // Newline
                    out.write(encoder.encode(x509Cert.getEncoded()));
                    out.write(0x0a);  // Newline
                    out.write(END_CERT.getBytes(StandardCharsets.US_ASCII));
                    out.write(0x0a);  // Newline
                }
                printMessage("\nWrote root certificate to root.pem");
            } catch (Exception e) {
                printMessage("ERROR: could not write root.pem: " + e);
                throw new Exception("Extraction error: " + EXIT_WRITE_ROOT_CERT_ERROR);
            }
        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException | KeyStoreException | CertificateException | KeyManagementException e) {
            printMessage("ERROR: SSL Error: " + e);
            throw new Exception("Extraction error: " + EXIT_SSL_ERROR);
        } catch (UnknownHostException e) {
            printMessage("ERROR: Failed to lookup host: " + host);
            throw new Exception("Extraction error: " + EXIT_CONNECT_FAILURE);
        } catch (IOException e) {
            printMessage("ERROR: IO Failure: " + e);
            throw new Exception("Extraction error: " + EXIT_CONNECT_FAILURE);
        }
        return outputFile.getAbsolutePath();
    }

    private X509Certificate findAnchor(Set<TrustAnchor> anchors, Principal certName) {
        for (TrustAnchor anchor :
                anchors) {
            if (anchor.getTrustedCert().getSubjectX500Principal().equals(certName)) {
                return anchor.getTrustedCert();
            }
        }
        return null;
    }

    private void printMessage(String s) {
        log.info(s);
    }


    public String getVerifyCert() {
        return verifyCert;
    }

    public void setVerifyCert(String verifyCert) {
        this.verifyCert = verifyCert;
    }

    private Set<TrustAnchor> getTrustAnchors() throws IOException, KeyStoreException, CertificateException,
            NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        // Load the JDK's cacerts keystore file
        String filename = System.getProperty("java.home") + "/lib/security/cacerts".replace('/', File.separatorChar);
        KeyStore keystore;
        try (FileInputStream is = new FileInputStream(filename)) {
            keystore = KeyStore.getInstance(KeyStore.getDefaultType());
            keystore.load(is, "changeit".toCharArray());
        }

        // This class retrieves the trust anchor (root) CAs from the keystore
        PKIXParameters params = new PKIXParameters(keystore);
        return params.getTrustAnchors();
    }

    class CustomTrustManager implements X509TrustManager {

        @Override
        public void checkClientTrusted(X509Certificate[] x509Certificates, String s) throws CertificateException {
        }

        @Override
        public void checkServerTrusted(X509Certificate[] x509Certificates, String s) throws CertificateException {
            certsSent = x509Certificates.length;
            boolean badChain = false;
            for (X509Certificate cert : x509Certificates) {
                printMessage("Certificate: ");
                printMessage("  Subject: " + cert.getSubjectX500Principal());
                printMessage("  Issuer : " + cert.getIssuerX500Principal());

                // Check to make sure chain is okay
                if (lastIssuer != null && !cert. getSubjectX500Principal().equals(lastIssuer)) {
                    printMessage("ERROR: the certificate chain returned from the server looks incorrect.  The previous certificate's issuer does not match this certificate's subject!");
                    printMessage(String.format("  expected: %s\n  but found: %s", lastIssuer, cert. getSubjectX500Principal()));
                    badChain = true;
                }

                lastCert = cert;
                lastIssuer = cert.getIssuerX500Principal();
                lastSubject = cert. getSubjectX500Principal();
                certificateChain.add(cert);
            }

            if (badChain) {
                printMessage("Please fix the server's certificate chain and try again.");
                throw new CertificateException("Extraction error: " + EXIT_SERVER_CHAIN_ERROR);
            }
        }

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return new X509Certificate[0];
        }
    }

    public void verifyChain(List<X509Certificate> certificateChain, Set<TrustAnchor> anchors) throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, CertificateException, CertPathValidatorException {
        PKIXParameters params = new PKIXParameters( anchors );
        //params.setRevocationEnabled(false);
        CertificateFactory certFactory  = CertificateFactory.getInstance("X.509");
        Security.setProperty("ocsp.enable", "true");
        System.setProperty("com.sun.net.ssl.checkRevocation", "true");
        System.setProperty("com.sun.security.enableCRLDP", "true");
        CertPath certPath = certFactory.generateCertPath(certificateChain);
        CertPathValidator validator = CertPathValidator.getInstance( "PKIX" );
        CertPathValidatorResult result = validator.validate( certPath, params );
        System.out.println("Chain validated !");
        //System.out.println("Cert PAth Result: "+result.toString());
        //PKIXCertPathValidatorResult
    }
}