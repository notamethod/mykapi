/**
 *
 */
package com.notamethod.mkcore.utils;

import java.io.*;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertPath;
import java.security.cert.CertPathBuilderException;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.*;

import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOCase;
import org.apache.commons.io.filefilter.IOFileFilter;
import org.apache.commons.io.filefilter.TrueFileFilter;
import org.apache.commons.io.filefilter.WildcardFileFilter;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;


/**
 * @author Buck
 */
class TrustCertUtil {

    private static final String FILTRE_CERTIFICAT_X509 = "*.CER";
    private static final String X509_CERTIFICATE_TYPE = "X.509";
    private static final Logger log = LogManager.getLogger(TrustCertUtil.class);

    /**
     * .
     *
     * @return
     * @throws GeneralSecurityException
     */
    public static X509Certificate[] getTrustedCerts(String repertoireAC,
                                                    String provider) throws GeneralSecurityException {
        X509Certificate[] trustedCerts;
        // Chargement de la liste des certificats de confiance
        try {
            Set<X509Certificate> certs = listerCertificats(repertoireAC,
                    X509_CERTIFICATE_TYPE, provider);
            trustedCerts = new X509Certificate[certs.size()];
            int i = 0;
            for (X509Certificate certificat : certs) {
                trustedCerts[i++] = certificat;
            }
        } catch (IOException ioe) {
            throw new GeneralSecurityException(
                    "Problème de lecture des certificats de confiance de "
                            + repertoireAC, ioe);
        }

        return trustedCerts;
    }

    /**
     * Récupération des AC reconnues à partir d'un keystore.
     *
     * @return
     * @throws GeneralSecurityException
     */
    public static X509Certificate[] getTrustedCerts(KeyStore ks)
            throws GeneralSecurityException {
        Enumeration<String> en = ks.aliases();
        Set<X509Certificate> lstCerts = new HashSet<>();
        while (en.hasMoreElements()) {
            String alias = en.nextElement();
            lstCerts.add((X509Certificate) ks.getCertificate(alias));
        }
        X509Certificate[] trustedCerts = new X509Certificate[lstCerts.size()];
        int i = 0;
        for (X509Certificate cert : lstCerts) {
            trustedCerts[i++] = cert;
        }

        return trustedCerts;
    }

    /**
     * Concatene des fichiers .cer dans un fichier unique, en supprimant les
     * doublons.
     *
     * @return
     * @throws GeneralSecurityException
     * @throws IOException
     */
    public static void concatCerts(String srcPath, File destFile,
                                   String provider) throws GeneralSecurityException, IOException {
        String typeCert = X509_CERTIFICATE_TYPE;
        // Chargement de la liste des certificats de confiance

        Set<X509Certificate> certs = listerCertificats(srcPath, typeCert,
                provider);
        try( InputStream certStream = new FileInputStream(destFile)) {

            // remarque: un fichier .cer peut contenir plus d'un certificat
            Collection<X509Certificate> trustedCerts2 = chargerCertificatsX509(
                    certStream, typeCert, provider);
            certs.addAll(trustedCerts2);
        } catch (IOException ioe) {
            // empty file
        }

        try (OutputStream output = new FileOutputStream(destFile)) {
            for (X509Certificate certificat : certs) {
                output.write(certificat.getEncoded());
            }
        }

    }

    /**
     * Vérification chaine de certificats.
     *
     * @param anchors
     * @param certs
     * @param crls
     * @throws CertPathValidatorException         si le chemin de certification n'est pas valide
     * @throws KeyStoreException
     * @throws NoSuchAlgorithmException
     * @throws CertificateException
     * @throws IOException
     * @throws InvalidAlgorithmParameterException
     * @throws CertPathBuilderException
     * @throws NoSuchProviderException
     */
    private static void checkTrusted(X509Certificate[] anchors,
                                     Certificate[] certs, Collection<?> crls, String provider,
                                     boolean isCheckCrl) throws CertPathValidatorException,
            NoSuchAlgorithmException, CertificateException,
            InvalidAlgorithmParameterException, NoSuchProviderException {

        /* Construct a valid path. */
        List<TrustAnchor> listAnchors = new ArrayList<>();

        for (X509Certificate cert : anchors) {
            TrustAnchor ta = new TrustAnchor(cert, null);
            listAnchors.add(ta);
        }

        Set anchorSet = new HashSet(listAnchors);
        List<X509Certificate> lstChaine = new ArrayList<>();
        for (Certificate cc0 : certs) {
            lstChaine.add((X509Certificate) cc0);
        }
        CollectionCertStoreParameters params = new CollectionCertStoreParameters(
                lstChaine);
        CertStore store = CertStore.getInstance("Collection", params, provider);

        CertStore crlStore = null;
        if (isCheckCrl) {
            CollectionCertStoreParameters revoked = new CollectionCertStoreParameters(
                    crls);
            crlStore = CertStore.getInstance("Collection", revoked, provider);
        }

        // create certificate path
        CertificateFactory factory = CertificateFactory.getInstance(X509_CERTIFICATE_TYPE,
                provider);
        List certChain = new ArrayList();

        certChain.add(lstChaine.get(0));
        // certChain.add(interCert);

        CertPath certPath = factory.generateCertPath(certChain);
        // null));
        // perform validation
        CertPathValidator validator = CertPathValidator.getInstance("PKIX",
                provider);
        PKIXParameters param = new PKIXParameters(anchorSet);

        param.addCertStore(store);
        param.setDate(new Date());

        if (isCheckCrl) {
            param.addCertStore(crlStore);
            param.setRevocationEnabled(true);
        } else {
            param.setRevocationEnabled(false);
        }

        // CertPathValidatorResult result = validator.validate(certPath, param);
        validator.validate(certPath, param);
        if (log.isInfoEnabled()) {
            log.info("certificate path validated");
        }
    }

    private static Set<X509Certificate> listerCertificats(
            String aCertificatesDirectory, String typeCert, String provider,
            boolean recursive) throws IOException, GeneralSecurityException {
        List<X509Certificate> lstCert = new ArrayList<>();
        // Set<X509Certificate> lstCert = new HashSet<X509Certificate>();
        // recherche des certificats dans le répertoire (*.cer ou *.CER)

        IOFileFilter fileFilter = WildcardFileFilter.builder()
                .setWildcards(FILTRE_CERTIFICAT_X509)
                .setIoCase(IOCase.INSENSITIVE)
                .get();

        IOFileFilter dirFilter = recursive ? TrueFileFilter.INSTANCE : null;
        Collection<File> lstFichiers = FileUtils.listFiles(new File(
                aCertificatesDirectory), fileFilter, dirFilter);

        for (File fichier : lstFichiers) {
            Collection<X509Certificate> trustedCerts;
            try (InputStream certStream = new FileInputStream(fichier)) {
                // a file can contains more than one certificate
                trustedCerts = chargerCertificatsX509(
                        certStream, typeCert, provider);
            }
            lstCert.addAll(trustedCerts);
        }
        return new HashSet<>(
                lstCert);
    }

    private static Set<X509Certificate> listerCertificats(
            String aCertificatesDirectory, String typeCert, String provider)
            throws IOException, GeneralSecurityException {
        return listerCertificats(aCertificatesDirectory, typeCert, provider,
                false);
    }

    /**
     * Récupère une liste de certificats à partir d'un fichier .cer.
     *
     * @param aCertStream
     * @return
     * @throws GeneralSecurityException
     */
    private static Collection<X509Certificate> chargerCertificatsX509(
            InputStream aCertStream, String typeCert, String provider)
            throws GeneralSecurityException {
        // création d'une fabrique de certificat X509
        CertificateFactory cf = CertificateFactory.getInstance(typeCert,
                provider);

        // chargement du certificat
        return (Collection<X509Certificate>) cf
                .generateCertificates(aCertStream);
    }

    /**
     * Vérifie le chemin de certification d'un certificat.
     *
     * @param trusted : liste des certificats reconnus
     * @param certs   : chaîne de certification du certificat à contrôler
     * @throws IOException
     */
    public static void validate(X509Certificate[] trusted, Certificate[] certs,
                                String provider) throws
            GeneralSecurityException {
        checkTrusted(trusted, certs, null, provider, false);
    }

    /**
     * Récupère les AC reconnues à partir d'un Stream.
     *
     * @param securityProvider
     * @throws GeneralSecurityException
     */
    public static X509Certificate[] getTrustedCerts(InputStream certStream,
                                                    String securityProvider) throws GeneralSecurityException {
        Collection<X509Certificate> trustedCerts = chargerCertificatsX509(
                certStream, X509_CERTIFICATE_TYPE, securityProvider);
        // suppression des doublons
        Set<X509Certificate> trustedCertificates = new HashSet<>(
                trustedCerts);
        X509Certificate[] certsArray;
        // Chargement de la liste des certificats de confiance

        certsArray = new X509Certificate[trustedCertificates.size()];
        int i = 0;
        for (X509Certificate certificat : trustedCerts) {
            certsArray[i++] = certificat;
        }
        return certsArray;
    }

    /**
     * .
     *
     * @param repertoireAC
     * @param provider
     * @return
     */
    public static X509Certificate[] getAllTrustedCerts(String repertoireAC,
                                                       String provider) throws GeneralSecurityException {
        X509Certificate[] trustedCerts;
        // Chargement de la liste des certificats de confiance
        try {
            Set<X509Certificate> certs = listerCertificats(repertoireAC,
                    X509_CERTIFICATE_TYPE, provider, true);
            trustedCerts = new X509Certificate[certs.size()];
            int i = 0;
            for (X509Certificate certificat : certs) {
                trustedCerts[i++] = certificat;
            }
        } catch (IOException ioe) {
            throw new GeneralSecurityException(
                    "Problème de lecture des certificats de confiance de "
                            + repertoireAC, ioe);
        }

        return trustedCerts;
    }

    /**
     * @param subPath
     */
    public static X509Certificate[] getDefaultTrustedCerts(String subPath) {
        String javaHome = System.getProperty("java.home");
        File f;
        f = new File(javaHome, Objects.requireNonNullElse(subPath, "jre/lib/security/cacerts"));
        try (FileInputStream is = new FileInputStream(f)) {
            KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());

            String password = "changeit";
            keystore.load(is, password.toCharArray());
            return getTrustedCerts(keystore);
        } catch (FileNotFoundException e) {
            if (subPath == null)
                return getDefaultTrustedCerts("lib/security/cacerts");
            else
                e.printStackTrace();
        } catch (IOException | GeneralSecurityException e) {
            e.printStackTrace();
        }
        return null;
    }

    public static void main(String[] args) {
        X509Certificate[] certs = getDefaultTrustedCerts(null);
        for (X509Certificate cert : certs) {
            System.out.println(cert.getSubjectX500Principal());
        }
    }
}
