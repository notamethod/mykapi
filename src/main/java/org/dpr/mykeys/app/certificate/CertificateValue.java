package org.dpr.mykeys.app.certificate;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.GeneralName;

import org.dpr.mykeys.app.CertificateType;
import org.bouncycastle.jce.X509Principal;
import org.dpr.mykeys.app.ChildInfo;
import org.dpr.mykeys.app.ChildType;
import org.dpr.mykeys.app.X509Constants;
import org.dpr.mykeys.app.utils.CertificateUtils;
import org.dpr.mykeys.app.utils.PoliciesException;
import org.dpr.mykeys.app.utils.PoliciesUtil;
import org.jetbrains.annotations.NotNull;

import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.util.*;

public class CertificateValue implements ChildInfo<CertificateValue>, Cloneable {
    private static final Log log = LogFactory.getLog(CertificateValue.class);
    private final List<GeneralName> subjectNames = new ArrayList<>();
    private Certificate[] certificateChain;
    private PublicKey publicKey;
    private PrivateKey privateKey;
    private String algoPubKey;
    private String algoSig;
    private String issuer;
    private char[] password;
    private byte[] signature;
    private int keyLength;
    private final Hashtable x509PrincipalMap = new Hashtable();
    private final Map<String, String> subjectMap = new LinkedHashMap<>();


    private String freeSubject;
    private String alias;
    private boolean[] keyUsage = new boolean[9];
    private Date notBefore;
    private Date notAfter;
    private int duration;
    private byte[] digestSHA1;
    private byte[] digestSHA256;
    private boolean containsPrivateKey = false;
    private String chaineStringValue;
    private String crlDistributionURL;
    private X509Certificate certificate;
    private String policyNotice;
    private String policyCPS;
    private String policyID;
    private Map<String, String> otherParams;
    private List<CertificateValue> children;

    public CertificateValue() {
        super();
        // x509PrincipalModel = new X509PrincipalModel();
    }

    public CertificateValue(String alias2) {
        this.alias = alias2;
    }

    public CertificateValue(String alias2, X509Certificate cert, char[] charArray) throws GeneralSecurityException {
        this.alias = alias2;
        this.password = charArray;
        init(cert);
    }

    public CertificateValue(String alias2, X509Certificate cert) throws GeneralSecurityException {
        this.alias = alias2;

        init(cert);
    }

    public CertificateValue(X509Certificate[] certs) throws GeneralSecurityException {

        init(certs);
    }

    public Map<String, String> getOtherParams() {
        return otherParams;
    }

    public void setOtherParams(Map<String, String> otherParams) {
        this.otherParams = otherParams;
    }

    public int getDuration() {
        return duration;
    }

    public void setDuration(Integer dur) {
        if (dur == null) {
            dur = 0;
        }
        this.duration = dur;

    }

    public void setFreeSubject(String freeSubject) {
        this.freeSubject = freeSubject;
    }

    public String getIssuer() {
        return issuer;
    }

    public void setIssuer(String issuer) {
        this.issuer = issuer;
    }

    /**
     * Retourne le hasPrivateKey.
     *
     * @return boolean - le hasPrivateKey.
     */
    public boolean isContainsPrivateKey() {
        return containsPrivateKey;
    }

    /**
     * Affecte le hasPrivateKey.
     *
     * @param hasPrivateKey le hasPrivateKey à affecter.
     */
    public void setContainsPrivateKey(boolean hasPrivateKey) {
        this.containsPrivateKey = hasPrivateKey;
    }

    /**
     * Retourne le chaineStringValue.
     *
     * @return String - le chaineStringValue.
     */
    public String getChaineStringValue() {
        return chaineStringValue;
    }

    /**
     * Affecte le chaineStringValue.
     *
     * @param chaineStringValue le chaineStringValue à affecter.
     */
    public void setChaineStringValue(String chaineStringValue) {
        this.chaineStringValue = chaineStringValue;
    }

    private void init(X509Certificate[] certs) throws GeneralSecurityException {
        init(certs[0]);
        this.setCertificateChain(certs);
        if (certs != null) {
            StringBuilder bf = new StringBuilder();
            for (Certificate chainCert : certs) {
                bf.append(chainCert.toString());
            }
            setChaineStringValue(bf.toString());
        }
    }

    /**
     * Initialize certificate
     *
     * @param certX509
     * @throws GeneralSecurityException
     */
    private void init(X509Certificate certX509) throws GeneralSecurityException {
        if (certX509 == null) {
            log.warn("X509 certificate is null");
            return;
        }
        this.setCertificate(certX509);
        Map<ASN1ObjectIdentifier, String> oidMap = new HashMap<>();
        this.setAlgoPubKey(certX509.getPublicKey().getAlgorithm());
        this.setAlgoSig(certX509.getSigAlgName());
        this.setSignature(certX509.getSignature());
        if (certX509.getPublicKey() instanceof RSAPublicKey) {
            this.setKeyLength(((RSAPublicKey) certX509.getPublicKey()).getModulus().bitLength());
            String aa = ((RSAPublicKey) certX509.getPublicKey()).getModulus().toString(16);
        }
        this.setPublicKey(certX509.getPublicKey());
        //why ?
        certX509.getSubjectX500Principal().getName("RFC2253");
        X500Name name = new X500Name(certX509.getSubjectX500Principal().getName("RFC2253"));

        this.x509NameToMap(name);
        this.setKeyUsage(certX509.getKeyUsage());
        this.setNotBefore(certX509.getNotBefore());
        this.setNotAfter(certX509.getNotAfter());
        try {
            this.setOtherParams(PoliciesUtil.getExtensionPolicies(certX509));
        } catch (PoliciesException e) {
            e.printStackTrace();
        }
//        this.setPolicyCPS(String.valueOf(X509Util.getPolicy(certX509, PolicyQualifierId.id_qt_cps)));
//        this.setPolicyNotice(String.valueOf(X509Util.getPolicy(certX509, PolicyQualifierId.id_qt_unotice)));
//        System.out.println(this.getPolicyCPS());
//        System.out.println(this.getPolicyNotice());
        MessageDigest md = MessageDigest.getInstance("SHA-1");
        md.update(certX509.getEncoded());

        this.setDigestSHA1(md.digest());
        md = MessageDigest.getInstance("SHA-256");
        md.update(certX509.getEncoded());

        this.setDigestSHA256(md.digest());
    }

    public String toString() {
        return alias;
    }

    public String getSubjectString() {
        return subjectMap.toString();
    }

    /**
     * @return the publicKey
     */
    public PublicKey getPublicKey() {
        return publicKey;
    }

    /**
     * @param publicKey the publicKey to set
     */
    public void setPublicKey(PublicKey publicKey) {
        this.publicKey = publicKey;
    }

    /**
     * @return the privateKey
     */
    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    /**
     * @param privateKey the privateKey to set
     */
    public void setPrivateKey(PrivateKey privateKey) {
        this.containsPrivateKey = true;
        this.privateKey = privateKey;
    }

    /**
     * @return the algo
     */
    public String getAlgoPubKey() {
        return algoPubKey;
    }

    /**
     * @param algo the algo to set
     */
    public void setAlgoPubKey(String algo) {
        this.algoPubKey = algo;
    }

    /**
     * @return the keyLength
     */
    public int getKeyLength() {
        return keyLength;
    }

    /**
     * @param keyLength the keyLength to set
     */
    public void setKeyLength(int keyLength) {
        this.keyLength = keyLength;
    }

    /**
     * @param keyLength the keyLength to set
     */
    public void setKeyLength(String keyLength) {
        this.keyLength = Integer.valueOf(keyLength);
    }

    /**
     * @return the algoSig
     */
    public String getAlgoSig() {
        return algoSig;
    }

    /**
     * @param algoSig the algoSig to set
     */
    public void setAlgoSig(String algoSig) {
        this.algoSig = algoSig;
    }

    /**
     * @return the password
     */
    public char[] getPassword() {
        return password;
    }

    /**
     * @param password the password to set
     */
    public void setPassword(char[] password) {
        this.password = password;
    }

    /**
     * @return the x509PrincipalMap
     */
    public Hashtable getX509PrincipalMap() {
        return x509PrincipalMap;
    }

    /**
     * @param sourceMap the x509PrincipalMap to set
     */
    @Deprecated
    public void setX509PrincipalMapOld(Map<String, String> sourceMap) {

        x509PrincipalMap.put(X509Principal.C, sourceMap.get("x509PrincipalC"));
        x509PrincipalMap.put(X509Principal.O, sourceMap.get("x509PrincipalO"));
        x509PrincipalMap.put(X509Principal.L, sourceMap.get("x509PrincipalL"));
        x509PrincipalMap
                .put(X509Principal.ST, sourceMap.get("x509PrincipalST"));
        x509PrincipalMap.put(X509Principal.E, sourceMap.get("x509PrincipalE"));
        x509PrincipalMap
                .put(X509Principal.CN, sourceMap.get("x509PrincipalCN"));

    }

    public String getFreeSubject() {
        return freeSubject;
    }

    public X500Name subjectMapToX500Name() {
        X500NameBuilder nameBuilder = new X500NameBuilder(BCStyle.INSTANCE);

        Set setKey = subjectMap.keySet();
        for (Object aSetKey : setKey) {
            String key = (String) aSetKey;
            String value = subjectMap.get(key);
            Object oidKey = null;
            try {
                oidKey = BCStyle.INSTANCE.attrNameToOID(key.toLowerCase());
                if (oidKey != null && value != null && !value.equals("")) {
                    nameBuilder.addRDN((ASN1ObjectIdentifier) oidKey, subjectMap.get(key));
                    // i++;
                } else {
                    log.error("No OID: " + key);
                }
            } catch (Exception e) {
                log.error("No OID: " + key);
            }

        }
        return nameBuilder.build();
    }


    public X500Name freeSubjectToX500Name() {
        return new X500Name(freeSubject);
    }
    /**
     * @return the alias
     */
    public String getAlias() {
        return alias;
    }

    /**
     * @param alias the alias to set
     */
    public void setAlias(String alias) {
        this.alias = alias;
    }

    /**
     * put X500Name date into key-value map
     *
     * @param name
     */
    private void x509NameToMap(X500Name name) {


        ASN1ObjectIdentifier[] v = name.getAttributeTypes();

        //  /** PKCS#9: 1.2.840.113549.1.9.1 */
        //static final ASN1ObjectIdentifier    pkcs_9_at_emailAddress        = pkcs_9.branch("1").intern();

        for (RDN rdn : name.getRDNs()) {
            AttributeTypeAndValue[] atrs = rdn.getTypesAndValues();
            for (AttributeTypeAndValue atr : atrs) {

                String val = atr.getValue().toString();

                //String type = RFC4519Style.INSTANCE.oidToDisplayName(atrs[i].getType());
                String type = BCStyle.INSTANCE.oidToDisplayName(atr.getType());

                if (log.isDebugEnabled()) {
                    log.debug(type + ":" + val);


                }
                if (null == type) {
                    log.error("o.i.d type not found for " + atr.getType());

                } else
                    subjectMap.put(type.toUpperCase(), val);
            }


        }

    }

    /**
     * @return the subjectMap
     */
    public Map<String, String> getSubjectMap() {
        return subjectMap;
    }

    /**
     * @param elementMap the subjectMap to set
     */
    public void setSubjectMap(Map<String, Object> elementMap) {
        Iterator iter = elementMap.keySet().iterator();
        this.subjectMap.clear();
        while (iter.hasNext()) {
            String key = (String) iter.next();
            Object value = elementMap.get(key);
            if (value instanceof String) {
                this.subjectMap.put(key, (String) value);
            }
        }

    }

    public void setSubjectMap(String name) {
        this.subjectMap.clear();
        for (String pair : name.split(",")) {
            String[] value = pair.split("=");
            subjectMap.put(value[0], value[1]);
        }

    }

    public byte[] getSignature() {
        return signature;
    }

    private void setSignature(byte[] sig) {
        signature = sig;

    }

    /**
     * @return the keyUsage
     */
    public boolean[] getKeyUsage() {
        return keyUsage;
    }

    /**
     * @param keyUsage the keyUsage to set
     */
    public void setKeyUsage(boolean[] keyUsage) {
        this.keyUsage = keyUsage;
    }

    public int getIntKeyUsage() {
        int iku = 0;
        if (keyUsage != null) {
            for (int i = 0; i < keyUsage.length; i++) {
                if (keyUsage[i]) {
                    iku = iku | X509Constants.keyUsageInt[i];
                }
            }
        }
        return iku;
    }

    /**
     * @return the notBefore
     */
    public Date getNotBefore() {
        return notBefore;
    }

    /**
     * @param notBefore the notBefore to set
     */
    public void setNotBefore(Date notBefore) {
        this.notBefore = notBefore;
    }

    /**
     * @return the notAfter
     */
    public Date getNotAfter() {
        return notAfter;
    }

    /**
     * @param notAfter the notAfter to set
     */
    public void setNotAfter(Date notAfter) {
        this.notAfter = notAfter;
    }

    /**
     * @return the digestSHA1
     */
    public byte[] getDigestSHA1() {
        return digestSHA1;
    }

    /**
     * @param digestSHA1 the digestSHA1 to set
     */
    private void setDigestSHA1(byte[] digestSHA1) {
        this.digestSHA1 = digestSHA1;
    }

    // public String getCrlDistributionURL() {
    // return el "http://xxx.crl";
    // }

    /**
     * @return the digestSHA256
     */
    public byte[] getDigestSHA256() {
        return digestSHA256;
    }

    /**
     * @param digestSHA256 the digestSHA256 to set
     */
    private void setDigestSHA256(byte[] digestSHA256) {
        this.digestSHA256 = digestSHA256;
    }

    public String getPolicyID() {
        if (policyID == null)
            return "2.16.250.1.114412.1.3.0.27";
        return policyID;

        //2.16.250.113556.1.8000.2554.58763.53606.25287.17664.43781.22216.52932.5775
    }

    public void setPolicyID(String policyID) {
        this.policyID = policyID;
    }

    /**
     * .
     *
     * <BR>
     *
     * @return
     */
    public Certificate[] getCertificateChain() {

        return certificateChain;
    }

    /**
     * .
     *
     * <BR>
     *
     * @param certificateChain2
     */
    public void setCertificateChain(Certificate[] certificateChain2) {
        certificateChain = certificateChain2;

    }

    /**
     * Retourne le crlDistributionURL.
     *
     * @return String - le crlDistributionURL.
     */
    public String getCrlDistributionURL() {
        return crlDistributionURL;
    }

    /**
     * Affecte le crlDistributionURL.
     *
     * @param crlDistributionURL le crlDistributionURL à affecter.
     */
    public void setCrlDistributionURL(String crlDistributionURL) {
        this.crlDistributionURL = crlDistributionURL;
    }

    /**
     * Retourne le certificate.
     *
     * @return X509Certificate - le certificate.
     */
    public X509Certificate getCertificate() {
        if (certificate == null && certificateChain != null)
            return (X509Certificate) certificateChain[0];
        return certificate;
    }

    /**
     * Affecte le certificate.
     *
     * @param certificate le certificate à affecter.
     */
    public void setCertificate(X509Certificate certificate) {
        this.certificate = certificate;
    }

    /**
     * Retourne le policyNotice.
     *
     * @return String - le policyNotice.
     */
    public String getPolicyNotice() {
        return policyNotice;
    }

    /**
     * Affecte le policyNotice.
     *
     * @param policyNotice le policyNotice à affecter.
     */
    public void setPolicyNotice(String policyNotice) {
        this.policyNotice = policyNotice;
    }

    /**
     * Retourne le policyCPS.
     *
     * @return String - le policyCPS.
     */
    public String getPolicyCPS() {
        return policyCPS;
    }

    /**
     * Affecte le policyCPS.
     *
     * @param policyCPS le policyCPS à affecter.
     */
    public void setPolicyCPS(String policyCPS) {
        this.policyCPS = policyCPS;
    }

    /**
     * .
     *
     * <BR>
     *
     * @return
     */
    public String getName() {
        if (subjectMap != null) {
            return subjectMap.get("CN");
        }
        return alias;
    }

    public CertificateValue setDnsNames(String... dnsNames) {
        for (String name : dnsNames) {
            subjectNames.add(new GeneralName(GeneralName.dNSName, name));
        }
        return this;
    }

    /**
     * Set subject's IP Address (server).
     *
     * @param ipAddresses
     * @return
     */
    public CertificateValue setIpAddresses(String... ipAddresses) {
        for (String address : ipAddresses) {
            subjectNames.add(new GeneralName(GeneralName.iPAddress, address));
        }
        return this;
    }

    /**
     * Set subject's directory names. I think this refers to alternate X.500
     * principal names, not filesystem directories.
     *
     * @param dirNames
     * @return
     */
    public CertificateValue setDirectoryNames(String... dirNames) {
        for (String name : dirNames) {
            subjectNames.add(new GeneralName(GeneralName.directoryName, name));
        }
        return this;
    }

    public Object clone() {
        CertificateValue certificate = null;
        try {
            // On récupère l'instance à renvoyer par l'appel de la
            // méthode super.clone()
            certificate = (CertificateValue) super.clone();
        } catch (CloneNotSupportedException cnse) {
            // Ne devrait jamais arriver car nous implémentons
            // l'interface Cloneable
            cnse.printStackTrace(System.err);
        }


        // on renvoie le clone
        return certificate;
    }

    public boolean isAcceptChildAC() {
        return isContainsPrivateKey() && (CertificateUtils.isKeyUsage(getKeyUsage(), X509Constants.USAGE_CERTSIGN));
    }

    public CertificateType getType() {
        if (isContainsPrivateKey()) {
            if (CertificateUtils.isKeyUsage(getKeyUsage(), X509Constants.USAGE_CERTSIGN))
                return CertificateType.AC;
            return CertificateType.STANDARD;
        }
        return null;
    }


    public void setChildren(List<CertificateValue> children) {
        this.children = children;
    }

    public List<CertificateValue> getChildren() {
        return children;
    }


    @Override
    public int compareTo(@NotNull CertificateValue o) {
        return this.getSubjectString().compareTo(o.getSubjectString());
    }

    public Date getFrom() {

        if (getDuration() > 0 || null == getNotBefore()) {
            return new Date();

        } else {
            return getNotBefore();

        }

    }

    public Date getTo() {

        if (getDuration() > 0) {

            LocalDateTime ldt = LocalDateTime.ofInstant(getNotBefore().toInstant(), ZoneId.systemDefault());
            ZonedDateTime zdt = ldt.plusYears(getDuration()).atZone(ZoneId.systemDefault());
            notAfter = Date.from(zdt.toInstant());
        }
        return notAfter;

    }

}
