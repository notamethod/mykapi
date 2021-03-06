package org.dpr.mykeys.app.utils;

import org.apache.commons.codec.binary.Hex;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.x509.extension.X509ExtensionUtil;

import javax.security.auth.x500.X500Principal;
import java.io.IOException;
import java.math.BigInteger;
import java.net.URISyntaxException;
import java.security.cert.CRLException;
import java.security.cert.X509Certificate;
import java.util.*;

public class X509Util {

    private final static Log log = LogFactory.getLog(X509Util.class);
    private static Map<String, String> mapNames = null;

    private X509Util() {
        super();
    }

    /**
     * @return the mapNames
     */
    public static Map<String, String> getMapNames() {
        if (mapNames == null) {
            mapNames = new LinkedHashMap<>();
            mapNames.put("CN", "x509.subject.name");
            mapNames.put("O", "x509.subject.organisation");
            mapNames.put("OU", "x509.subject.organisationUnit");
            mapNames.put("E", "x509.subject.email");
            mapNames.put("C", "x509.subject.country");
            mapNames.put("L", "x509.subject.location");
            mapNames.put("ST", "x509.subject.street");
        }
        return mapNames;
    }

    public static String toHexString(byte[] b, String separator, boolean upperCase) {
        StringBuilder retour = new StringBuilder();
        char[] car = Hex.encodeHex(b);
        for (int i = 0; i < car.length; i = i + 2) {
            retour.append(car[i]);
            retour.append(car[i + 1]);
            retour.append(separator);
        }
        if (upperCase) {
            return retour.toString().toUpperCase();
        } else {
            return retour.toString().toLowerCase();
        }
    }

    public static String toHexString(BigInteger bi, String separator, boolean upperCase) {
        String retour;
        String converted = bi.toString(16);
        char[] charArray = converted.toCharArray();
        StringBuilder retourBuilder = new StringBuilder();
        for (int i = 0; i < charArray.length - 1; i = i + 2) {
            retourBuilder.append(charArray[i]);
            retourBuilder.append(charArray[i + 1]);
            retourBuilder.append(separator);
        }
        retour = retourBuilder.toString();
        if (upperCase) {
            return retour.toUpperCase();
        } else {
            return retour.toLowerCase();
        }
    }


    public static PolicyInformation[] getPolicies(X509Certificate cert) {
        byte[] policyBytes = cert.getExtensionValue(Extension.certificatePolicies.toString());
        try {
            if (policyBytes != null) {
                CertificatePolicies policies = CertificatePolicies.getInstance(X509ExtensionUtil.fromExtensionValue(policyBytes));
                PolicyInformation[] policyInformation = policies.getPolicyInformation();
                return policyInformation;
            }
        } catch (IOException e) {
            log.error("get policies error", e);
        }
        return null;

    }

    public static ASN1Encodable getPolicy(X509Certificate cert, PolicyQualifierId id) {
        ASN1Encodable policy = null;
        PolicyInformation[] policyInformation = getPolicies(cert);
        if (policyInformation != null) {
            for (PolicyInformation pInfo : policyInformation) {
                ASN1Sequence policyQualifiers = null;
                try {
                    policyQualifiers = (ASN1Sequence) pInfo.getPolicyQualifiers().getObjectAt(0);
                } catch (Exception e) {
                    Object o = pInfo.getPolicyQualifiers().getObjectAt(0);
                    id.toString().equals(o.toString());
                }
                if (id.equals(policyQualifiers.getObjectAt(0)))
                    return policyQualifiers.getObjectAt(1);
            }
        }
        return policy;
    }

    public static Map<ASN1ObjectIdentifier, String> getSubjectMap(X509Certificate x509Certificate) {
        X500Principal x500Principal = x509Certificate.getSubjectX500Principal();
        return getInfosMap(x500Principal);
    }

    public static Map<ASN1ObjectIdentifier, String> getIssuerMap(X509Certificate x509Certificate) {
        X500Principal x500Principal = x509Certificate.getIssuerX500Principal();
        return getInfosMap(x500Principal);
    }

    public static Map<ASN1ObjectIdentifier, String> getInfosMap(X500Principal x500Principal) {
        Map<ASN1ObjectIdentifier, String> subjectMap = new HashMap<>();
        if (x500Principal == null) {
            return subjectMap;
        }
        String principalName = x500Principal.getName();
        if (StringUtils.isBlank(principalName)) {
            return subjectMap;
        }
        X500Name x509Name = new X500Name(principalName);
        ASN1ObjectIdentifier[] v = x509Name.getAttributeTypes();

        for (RDN rdn : x509Name.getRDNs()) {
            AttributeTypeAndValue[] atrs = rdn.getTypesAndValues();
            for (AttributeTypeAndValue atr : atrs) {

                String val = atr.getValue().toString();
                ASN1ObjectIdentifier type = atr.getType();
                if (log.isDebugEnabled()) {
                    log.debug(type + ":" + val);
                }
                subjectMap.put(type, val);
            }

        }
        return subjectMap;
    }

    /**
     * Récupération des points de distribution des CRL.
     *
     * <BR>
     *
     * @param certX509
     * @throws CRLException
     * @throws IOException
     * @throws URISyntaxException
     */
    public static Set<String> getDistributionPoints(X509Certificate certX509) {
        Set<String> distPointSet = new HashSet<>();
        byte[] extVal = certX509.getExtensionValue(Extension.cRLDistributionPoints.getId());
        byte[] extension = certX509.getExtensionValue(Extension.cRLDistributionPoints.toString());
        if (extension == null) {
            if (log.isWarnEnabled()) {
                log.warn("Pas de CRLDistributionPoint pour: "
                        + certX509.getSubjectDN());//
            }
            return distPointSet;
        }

        CRLDistPoint distPoints;
        try {
            distPoints = CRLDistPoint.getInstance(X509ExtensionUtil
                    .fromExtensionValue(extension));
        } catch (Exception e) {
            if (log.isWarnEnabled()) {
                log.warn("Extension de CRLDistributionPoint non reconnue pour: "
                        + certX509.getSubjectDN());//
            }
            if (log.isDebugEnabled()) {
                log.debug(e);
            }
            return distPointSet;
        }

        DistributionPoint[] pointsDistrib;
        try {
            pointsDistrib = distPoints.getDistributionPoints();
        } catch (Exception e) {
            if (log.isWarnEnabled()) {
                log.warn("Extension de CRLDistributionPoint non reconnue pour: "
                        + certX509.getSubjectDN());//
            }
            if (log.isDebugEnabled()) {
                log.debug(e);
            }
            return distPointSet;
        }
        for (DistributionPoint distributionPoint : pointsDistrib) {
            DistributionPointName name = distributionPoint
                    .getDistributionPoint();

            GeneralName[] gns = ((GeneralNames) name.getName()).getNames();

            for (GeneralName gn : gns) {

                if (gn.getTagNo() == GeneralName.uniformResourceIdentifier) {

                    //FIXME to test
                    String distPointName = (gn.getName())
                            .toString();

                    distPointSet.add(distPointName);

                    if (log.isDebugEnabled()) {
                        log.debug("récupération url: " + distPointName);
                    }

                }

            }
        }
        return distPointSet;

    }

    public static List<String> getExtendedKeyUsages(X509Certificate certificate) throws Exception {
        List<String> keys = new ArrayList<>();
        byte[] kuBytes = certificate.getExtensionValue(Extension.extendedKeyUsage.toString());
        if (kuBytes != null) {
            ExtendedKeyUsage eku = null;
            try {
                eku = ExtendedKeyUsage.getInstance(X509ExtensionUtil.fromExtensionValue(kuBytes));
            } catch (IOException e) {
                throw new Exception("invalid key usages informations", e);
            }
            int k = 1;
            if (eku != null) {
                for (KeyPurposeId pki : eku.getUsages()) {
                    keys.add(BCUtil.extendedKeyUsages.getOrDefault(pki, pki.toString()));
                }
            }
        }

        return keys;
    }


}
