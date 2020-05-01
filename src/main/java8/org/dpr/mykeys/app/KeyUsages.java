package org.dpr.mykeys.app;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.dpr.mykeys.app.X509Constants;

import java.util.List;
import java.util.Map;

public class KeyUsages {
    public static final String[] keyUsageLabel = new String[]{"digitalSignature", "nonRepudiation", "keyEncipherment",
			"dataEncipherment", "keyAgreement", "keyCertSign", "cRLSign", "encipherOnly", "decipherOnly" };

    public static final String[] ExtendedkeyUsageLabel = new String[]{"code signing",};

    public static final int USAGE_CERTSIGN = 5;
    public static int USAGE_CRLSIGN = 6;
    public static final int[] keyUsageInt = new int[]{KeyUsage.digitalSignature, KeyUsage.nonRepudiation,
			KeyUsage.keyEncipherment, KeyUsage.dataEncipherment, KeyUsage.keyAgreement, KeyUsage.keyCertSign,
			KeyUsage.cRLSign, KeyUsage.encipherOnly, KeyUsage.decipherOnly };

    public static int toInt(boolean[] keyUsage){
        System.out.println("java8");
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
        //Not needed but Multi-Release Jar not working well in Intellij
        return -1;
    }
}
