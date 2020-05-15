package org.dpr.mykeys.app.certificate;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.dpr.mykeys.app.ServiceException;
import org.dpr.mykeys.app.utils.ProviderUtil;

import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Map;

import static org.dpr.mykeys.app.utils.CertificateUtils.randomBigInteger;

public class CertificateBuilder implements CertificateGeneratorExtensions {

    private final String DEFAULT_SIGNATURE_ALGORITHM="SHA256WithRSAEncryption";
    private final String DEFAULT_KEY_ALGORITHM="RSA";
    private final int DEFAULT_KEY_SIZE=2048;

    private final Log log = LogFactory.getLog(CertificateBuilder.class);
    private static final int AUTH_VALIDITY = 999;
    private static final int DEFAULT_VALIDITY = 365;

    private X509Certificate issuerCertificate = null;
    private PrivateKey issuerPrivateKey;

    private KeyPair keyPair  = null;
    private Date startingDate;
    private Date endingDate;
    private String alias;
    private String signatureAlgorithm = DEFAULT_SIGNATURE_ALGORITHM;
    private BigInteger serialNumber;
    private String freeSubject;
    private int keyUsage;

    public CertificateBuilder() {
        super();
    }
    public CertificateBuilder(X509Certificate issuerCertificate, PrivateKey issuerPrivateKey) {
        this.issuerPrivateKey = issuerPrivateKey;
        this.issuerCertificate = issuerCertificate;
    }

    @Override
    public void addExtensions(X509v3CertificateBuilder certGen, Map<String, String> parameters) throws IOException {
        Extension en = new Extension(Extension.basicConstraints,
                false,
                new BasicConstraints(false).getEncoded());
        certGen.addExtension(en);

    }



    public CertificateBuilder withAlias(String alias){
        this.alias = alias;
        return this;
    }
    public CertificateBuilder withSerial(BigInteger serial){
        this.serialNumber = serial;
        return this;
    }

    public CertificateBuilder withSubject(String subject){
        this.freeSubject = subject;
        return this;
    }
    public CertificateBuilder withKeyUsage(int keyUsage){
        this.keyUsage = keyUsage;
        return this;
    }

    public CertificateBuilder withKeyPair(KeyPair keyPair){
        this.keyPair = keyPair;
        return this;
    }

    public CertificateBuilder withStartingDate(Date date){
        this.startingDate = date;
        return this;
    }
    public CertificateBuilder withEndingDate(Date date){
        this.endingDate = date;
        return this;
    }
    public CertificateBuilder withDuration(int duration){
       //TODO duration
        return this;
    }
    public CertificateBuilder withIssuerPrivateKey(PrivateKey pk){
        this.issuerCertificate = issuerCertificate;
        return this;
    }

    public CertificateBuilder withSignatureAlgorithm(String algo){
        this.signatureAlgorithm=algo;
        return this;
    }
    public X509Certificate build()
            throws Exception {

        // defaults -------------------------------------------
        //keypair
        if (keyPair == null){
            log.info("generating default keypair");
            CertificateManager certificateManager = new CertificateManager();
            keyPair = certificateManager.generateKeyPair(DEFAULT_KEY_ALGORITHM, DEFAULT_KEY_SIZE);
        }

        if (null == serialNumber)
            serialNumber = randomBigInteger(30);

        if (StringUtils.isBlank(alias)) {
            alias=serialNumber.toString(16);
        }

        X500Name subject = freeSubject == null ? new X500Name("CN=user") : new X500Name(freeSubject);

        //issuer
        X500Name issuerDN;
        if (issuerCertificate != null) {
            log.info("certificate generated from issuer..." + issuerCertificate.getSubjectDN());
            issuerDN = X500Name.getInstance(issuerCertificate.getSubjectX500Principal().getEncoded());
        } else {
            issuerDN = subject;
        }

        if (startingDate == null){
            startingDate= new Date();
            if (endingDate == null) {
                endingDate = new Date(System.currentTimeMillis() + (DEFAULT_VALIDITY * 86400000L));
            }
        }


        X509v3CertificateBuilder certGen = new JcaX509v3CertificateBuilder(issuerDN,
                serialNumber,
                startingDate,
                endingDate,
                subject,
                keyPair.getPublic());

        JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();

        addExtensions(certGen, null);
        certGen.addExtension(Extension.keyUsage, true, new KeyUsage(keyUsage));
        certGen.addExtension(Extension.subjectKeyIdentifier, false, extUtils.createSubjectKeyIdentifier(keyPair.getPublic()));

        PrivateKey pk;
        PublicKey pubKey;

        // FIXME: à vérifier en cas de auto signé
        if (issuerCertificate != null && issuerPrivateKey ==null) {
            throw new ServiceException("issuer private key can not be null");
        }
        if (issuerCertificate != null) {
            certGen.addExtension(Extension.authorityKeyIdentifier, false,
                    extUtils.createAuthorityKeyIdentifier(issuerCertificate));
            pk = issuerPrivateKey;
            pubKey = issuerCertificate.getPublicKey();
        } else {
            certGen.addExtension(Extension.authorityKeyIdentifier, false,
                    extUtils.createAuthorityKeyIdentifier(keyPair.getPublic()));
            pk = keyPair.getPrivate();
            pubKey = keyPair.getPublic();
        }

        //TODO policies

        // self signed ?



        ContentSigner signer = new JcaContentSignerBuilder(signatureAlgorithm).build(pk);

        X509CertificateHolder certHolder = certGen.build(signer);
        log.info("certificate generated");
        X509Certificate cert = new JcaX509CertificateConverter().setProvider(ProviderUtil.provider).getCertificate(certHolder);
        // TODO: let generate expired certificate for test purpose ?
        try {
            cert.checkValidity(new Date());
        } catch (Exception e) {
            log.warn("invalid certificate", e);
        }

        cert.verify(pubKey);
        log.info("certificate verified");
        // FIXME: gérer la chaine
//        X509Certificate[] certChain = null;
//        // FIXME: gérer la chaine de l'émetteur
//        if (certIssuer != null && certIssuer.getCertificateChain() != null) {
//            log.info("adding issuer " + certIssuer.getName() + "'s certicate chain to certificate");
//            certChain = new X509Certificate[certIssuer.getCertificateChain().length + 1];
//            System.arraycopy(certIssuer.getCertificateChain(), 0, certChain, 1,
//                    certIssuer.getCertificateChain().length);
//            certChain[0] = cert;
//            // certChain[1] = certIssuer.getCertificate();
//        } else if (certIssuer != null && certIssuer.getCertificate() != null) {
//            log.error("FIXME");
//            certChain = new X509Certificate[2];
//            certChain[0] = cert;
//            certChain[1] = certIssuer.getCertificate();
//        } else {
//            certChain = new X509Certificate[]{cert};
//        }
//        CertificateValue certReturn = new CertificateValue(certChain);
//        certReturn.setPrivateKey(keypair.getPrivate());
//        certReturn.setPublicKey(keypair.getPublic());
//        certReturn.setPassword(certModel.getPassword());

        return cert;

    }

    private ASN1EncodableVector getPolicyInformation(String policyOID, String cps, String unotice) {

        ASN1EncodableVector qualifiers = new ASN1EncodableVector();

        if (!StringUtils.isEmpty(unotice)) {
            UserNotice un = new UserNotice(null, new DisplayText(DisplayText.CONTENT_TYPE_UTF8STRING, unotice));
            PolicyQualifierInfo pqiUNOTICE = new PolicyQualifierInfo(PolicyQualifierId.id_qt_unotice, un);
            qualifiers.add(pqiUNOTICE);
        }
        if (!StringUtils.isEmpty(cps)) {

            PolicyQualifierInfo pqiCPS = new PolicyQualifierInfo(cps);
            PolicyInformation pi = new PolicyInformation(PolicyQualifierId.id_qt_cps,
                    new DERSequence(pqiCPS));
            qualifiers.add(pi);
        }

//		PolicyInformation policyInformation = new PolicyInformation(new ASN1ObjectIdentifier(policyOID),
//				new DERSequence(qualifiers));
//wildcard policy 2.5.29.32.0
        return qualifiers;

    }

    public CertificateValue createCertificateAuth(String id, char[] charArray, KeyPair keypair) throws ServiceException {

        // X500Name owner = new X500Name("CN=" + fqdn);
        X500Name subject = new X500Name("CN=" + id);
        BigInteger serial = new BigInteger(32, new SecureRandom());
        Date from = new Date();
        Date to = new Date(System.currentTimeMillis() + (AUTH_VALIDITY * 86400000L));

        // Prepare the information required for generating an X.509 certificate.
        X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(subject, serial, from, to, subject,
                keypair.getPublic());

        CertificateValue value = null;
        try {
            ContentSigner signer = new JcaContentSignerBuilder("SHA256WithRSAEncryption").build(keypair.getPrivate());
            X509CertificateHolder certHolder = builder.build(signer);
            X509Certificate cert = new JcaX509CertificateConverter().setProvider(ProviderUtil.provider).getCertificate(certHolder);

            cert.verify(keypair.getPublic());
            value = new CertificateValue(id, cert);
        } catch (GeneralSecurityException | OperatorCreationException e) {
            throw new ServiceException("create auth error", e);
        }
        value.setPrivateKey(keypair.getPrivate());
        return value;


    }


//    DERSequence subjectAlternativeNames = new DERSequence(new ASN1Encodable[] {
//            new GeneralName(GeneralName.dNSName, "localhost"),
//            new GeneralName(GeneralName.dNSName, "127.0.0.1")
//    });
//    builder.addExtension(Extension.subjectAlternativeName, false, subjectAlternativeNames);
}
