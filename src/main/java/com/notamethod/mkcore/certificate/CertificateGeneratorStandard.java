package com.notamethod.mkcore.certificate;



import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
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
import com.notamethod.mkcore.utils.KeyUsages;
import com.notamethod.mkcore.utils.ServiceException;
import com.notamethod.mkcore.utils.ProviderUtil;

import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Map;

import static com.notamethod.mkcore.utils.CertificateUtils.randomBigInteger;

class CertificateGeneratorStandard implements CertificateGeneratorExtensions {

    private final Logger log = LogManager.getLogger(CertificateGeneratorStandard.class);
    private static final int AUTH_VALIDITY = 999;

    public CertificateGeneratorStandard() {
        super();
    }

    public void addExtensions(X509v3CertificateBuilder certGen, Map<String, String> parameters) throws IOException {


        Extension en = new Extension(Extension.basicConstraints,
                false,
                new BasicConstraints(false).getEncoded());
        certGen.addExtension(en);

    }

    public Certificate generate(KeyPair keypair, Certificate certModel, Certificate certIssuer)
            throws Exception {


        JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();


        // SerialNumber
        BigInteger serial = randomBigInteger(30);
        if (null == certModel.getAlias() || certModel.getAlias().isBlank()) {
            certModel.setAlias(serial.toString(16));
        }

        X500Name subject = certModel.getFreeSubject() == null ? certModel.subjectMapToX500Name() : certModel.freeSubjectToX500Name();

        //issuer
        X500Name issuerDN;
        if (certIssuer != null && certIssuer.getX509Certificate() != null) {
            log.info("certificate generated from issuer..." + certIssuer.getName());

            issuerDN = X500Name.getInstance(certIssuer.getX509Certificate().getSubjectX500Principal().getEncoded());
        } else {
            issuerDN = subject;
        }

        X509v3CertificateBuilder certGen = new JcaX509v3CertificateBuilder(issuerDN, serial, certModel.getFrom(), certModel.getTo(), subject,
                keypair.getPublic());


        addExtensions(certGen, null);
        certGen.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsages.toInt(certModel.getKeyUsage())));
        certGen.addExtension(Extension.subjectKeyIdentifier, false, extUtils.createSubjectKeyIdentifier(keypair.getPublic()));

        // FIXME: à vérifier en cas de auto signé
        if (certIssuer != null && certIssuer.getX509Certificate() != null) {
            certGen.addExtension(Extension.authorityKeyIdentifier, false, extUtils.createAuthorityKeyIdentifier(certIssuer.getX509Certificate()));
        } else {
            certGen.addExtension(Extension.authorityKeyIdentifier, false,
                    extUtils.createAuthorityKeyIdentifier(keypair.getPublic()));
        }

        if (null != certModel.getPolicyCPS() && !certModel.getPolicyCPS().isBlank()) {
            ASN1EncodableVector qualifiers = getPolicyInformation(certModel.getPolicyID(), certModel.getPolicyCPS(), certModel.getPolicyNotice());
            certGen.addExtension(Extension.certificatePolicies, false, new DERSequence(qualifiers));


//            PolicyQualifierInfo policyQualifierInfo = new PolicyQualifierInfo(certModel.getPolicyCPS());
//            PolicyInformation policyInformation = new PolicyInformation(PolicyQualifierId.id_qt_cps,
//                    new DERSequence(policyQualifierInfo));
//            ASN1EncodableVector certificatePolicies = new ASN1EncodableVector();
//            final UserNotice un = new UserNotice(null, new DisplayText(DisplayText.CONTENT_TYPE_UTF8STRING, certModel.getPolicyNotice()));
//            PolicyQualifierInfo not = new PolicyQualifierInfo(PolicyQualifierId.id_qt_unotice, un);
//            certificatePolicies.add(policyInformation);
//            certificatePolicies.add(not);
//            if (!certModel.getPolicyID().isEmpty()) {
//                PolicyInformation extraPolicyInfo = new PolicyInformation(new ASN1ObjectIdentifier(certModel.getPolicyID()),
//                        new DERSequence(new ASN1ObjectIdentifier("")));
//                certificatePolicies.add(extraPolicyInfo);
//            }


        }

        // gen.addExtension(X509Extensions.ExtendedKeyUsage, true,
        // new ExtendedKeyUsage(KeyPurposeId.id_kp_clientAuth));

        // self signed ?

        PrivateKey pk;
        PublicKey pubKey;
        if (certIssuer == null || certModel.getSubjectString().equalsIgnoreCase(certIssuer.getSubjectString())) {
            pk = keypair.getPrivate();
            pubKey = keypair.getPublic();
        } else {
            pk = certIssuer.getPrivateKey();
            pubKey = certIssuer.getPublicKey();
        }
        ContentSigner signer = new JcaContentSignerBuilder(certModel.getAlgoSig()).build(pk);

        X509CertificateHolder certHolder = certGen.build(signer);

        X509Certificate cert = new JcaX509CertificateConverter().setProvider(ProviderUtil.provider).getCertificate(certHolder);
        // TODO: let generate expired certificate for test purpose ?
        try {
            cert.checkValidity(new Date());
        } catch (Exception e) {
            log.warn("invalid certificate", e);
        }

        cert.verify(pubKey);

        X509Certificate[] certChain;
        // FIXME: gérer la chaine de l'émetteur
        if (certIssuer != null && certIssuer.getCertificateChain() != null) {
            log.info("adding issuer " + certIssuer.getName() + "'s certicate chain to certificate");
            certChain = new X509Certificate[certIssuer.getCertificateChain().length + 1];
            System.arraycopy(certIssuer.getCertificateChain(), 0, certChain, 1,
                    certIssuer.getCertificateChain().length);
            certChain[0] = cert;
            // certChain[1] = certIssuer.getCertificate();
        } else if (certIssuer != null && certIssuer.getX509Certificate() != null) {
            log.error("FIXME");
            certChain = new X509Certificate[2];
            certChain[0] = cert;
            certChain[1] = certIssuer.getX509Certificate();
        } else {
            certChain = new X509Certificate[]{cert};
        }
        Certificate certReturn = new Certificate(certChain);
        certReturn.setPrivateKey(keypair.getPrivate());
        certReturn.setPublicKey(keypair.getPublic());
        certReturn.setPassword(certModel.getPassword());

        return certReturn;

    }

    private ASN1EncodableVector getPolicyInformation(String policyOID, String cps, String unotice) {

        ASN1EncodableVector qualifiers = new ASN1EncodableVector();

        if (unotice!= null && !unotice.isBlank()) {
            UserNotice un = new UserNotice(null, new DisplayText(DisplayText.CONTENT_TYPE_UTF8STRING, unotice));
            PolicyQualifierInfo pqiUNOTICE = new PolicyQualifierInfo(PolicyQualifierId.id_qt_unotice, un);
            qualifiers.add(pqiUNOTICE);
        }
        if (cps!= null && !cps.isBlank()) {
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

    public Certificate createCertificateAuth(String id, char[] charArray, KeyPair keypair) throws ServiceException {

        X500Name subject = new X500Name("CN=" + id);
        BigInteger serial = new BigInteger(32, new SecureRandom());
        Date from = new Date();
        Date to = new Date(System.currentTimeMillis() + (AUTH_VALIDITY * 86400000L));

        // Prepare the information required for generating an X.509 certificate.
        X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(subject, serial, from, to, subject,
                keypair.getPublic());

        Certificate value;
        try {
            ContentSigner signer = new JcaContentSignerBuilder("SHA256WithRSAEncryption").build(keypair.getPrivate());
            X509CertificateHolder certHolder = builder.build(signer);
            X509Certificate cert = new JcaX509CertificateConverter().setProvider(ProviderUtil.provider).getCertificate(certHolder);

            cert.verify(keypair.getPublic());
            value = new Certificate(id, cert);
            log.info("certificate " + id + " generated");
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
