package org.dpr.mykeys.app;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.dpr.mykeys.app.X509Constants;

import java.util.List;
import java.util.Map;

public class KeyUsages {
    public static final String[] keyUsageKeys = new String[]{"digitalSignature", "nonRepudiation", "keyEncipherment",
			"dataEncipherment", "keyAgreement", "keyCertSign", "cRLSign", "encipherOnly", "decipherOnly" };

    public static final String[] ExtendedkeyUsageLabel = new String[]{"code signing",};

    public static final int USAGE_CERTSIGN = 5;
    public static int USAGE_CRLSIGN = 6;
    public static final int[] keyUsageInt = new int[]{KeyUsage.digitalSignature, KeyUsage.nonRepudiation,
			KeyUsage.keyEncipherment, KeyUsage.dataEncipherment, KeyUsage.keyAgreement, KeyUsage.keyCertSign,
			KeyUsage.cRLSign, KeyUsage.encipherOnly, KeyUsage.decipherOnly };

     static Map<String,Integer> map = Map.of(
            "digitalSignature", KeyUsage.digitalSignature,
            "nonRepudiation",KeyUsage.nonRepudiation,
            "keyEncipherment",KeyUsage.keyEncipherment,
            "dataEncipherment",KeyUsage.dataEncipherment,
            "keyAgreement",KeyUsage.keyAgreement,
            "keyCertSign",KeyUsage.keyCertSign,
            "cRLSign",KeyUsage.cRLSign,
            "encipherOnly",KeyUsage.encipherOnly,
            "decipherOnly",KeyUsage.decipherOnly);


    public static int toInt(boolean[] keyUsage){
        System.out.println("java14");
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
    public static int toInt(List<String> stringValues){
     int iku=0;
        for (String value:stringValues){
            int intValue = map.getOrDefault(value, 0);
            iku = iku | intValue;
        }
        return iku;

    }
}
