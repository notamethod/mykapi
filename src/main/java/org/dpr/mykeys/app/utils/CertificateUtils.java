package org.dpr.mykeys.app.utils;

import java.io.*;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.*;

public class CertificateUtils {

    Map<Integer, String> mapKeyUSage = new HashMap<>();
    private static SecureRandom secureRandom = new SecureRandom();

    public static String keyUsageToString(boolean[] keyUsage) {
        StringBuilder value = new StringBuilder();
        boolean isKeyUsage = false;
        if (keyUsage == null) {
            return "null";
        }
        for (int i = 0; i < keyUsage.length; i++) {
            if (keyUsage[i]) {
                isKeyUsage = true;
                value.append(", ").append(X509Constants.keyUsageLabel[i]);
            }
        }
        if (isKeyUsage) {
            return value.substring(1);
        } else {
            return null;
        }
    }

    public static List<String> keyUsageToList(boolean[] keyUsage) {
        List<String> kuList = new ArrayList<>();
        String value = "";
        boolean isKeyUsage = false;
        if (keyUsage == null) {
            return kuList;
        }
        for (int i = 0; i < keyUsage.length; i++) {
            if (keyUsage[i]) {
                isKeyUsage = true;
                kuList.add(X509Constants.keyUsageLabel[i]);
            }
        }
        return kuList;
    }



    public static Set<X509Certificate> loadX509Certs(InputStream aCertStream) throws GeneralSecurityException {

        CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");

        // chargement du certificat
        Collection<X509Certificate> certs = (Collection<X509Certificate>) cf.generateCertificates(aCertStream);
        return new HashSet<>(certs);
    }

    /**
     * get a random BigInteger
     *
     * @param numBits maximum bitLength of the new BigInteger
     * @return
     */
    public static BigInteger randomBigInteger(int numBits) {
        return new BigInteger(numBits, secureRandom);
    }
}
