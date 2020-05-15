package org.dpr.mykeys.app;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.dpr.mykeys.app.utils.KeyUsageEnum;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class KeyUsages {
    public static final String[] keyUsageLabel = new String[]{"digitalSignature", "nonRepudiation", "keyEncipherment",
			"dataEncipherment", "keyAgreement", "keyCertSign", "cRLSign", "encipherOnly", "decipherOnly" };

    public static final String[] ExtendedkeyUsageLabel = new String[]{"code signing",};

    public static final int USAGE_CERTSIGN = 5;
    public static int USAGE_CRLSIGN = 6;
    public static final int[] keyUsageInt = new int[]{KeyUsage.digitalSignature, KeyUsage.nonRepudiation,
			KeyUsage.keyEncipherment, KeyUsage.dataEncipherment, KeyUsage.keyAgreement, KeyUsage.keyCertSign,
			KeyUsage.cRLSign, KeyUsage.encipherOnly, KeyUsage.decipherOnly };

    static Map<String,Integer> map;
    /**
     * convert boolean keyusage array to int
     * @param keyUsage
     * @return
     */
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

    private static Map<String, Integer> getMap(){
        if (map!=null)
            return map;
         map = Stream.of(new Object[][] {
                {  "digitalSignature", KeyUsage.digitalSignature},
                { "nonRepudiation",KeyUsage.nonRepudiation },
                { "keyEncipherment",KeyUsage.keyEncipherment},
                {  "dataEncipherment",KeyUsage.dataEncipherment },
                { "keyAgreement",KeyUsage.keyAgreement },
                { "keyCertSign",KeyUsage.keyCertSign },
                { "cRLSign",KeyUsage.cRLSign },
                { "encipherOnly",KeyUsage.encipherOnly},
                { "decipherOnly",KeyUsage.decipherOnly }
        }).collect(Collectors.toMap(data -> (String) data[0], data -> (Integer) data[1]));
        return map;
    }
    public static String toString(int value){
        Map<Integer, String> invertedMap =
                map.entrySet()
                        .stream()
                        .collect(Collectors.toMap(Map.Entry::getValue, Map.Entry::getKey));
        return invertedMap.get(value);
    }

    public static boolean isKeyUsage(boolean[] keyUsage, int i) {
        if (keyUsage == null)
            return false;
        return i < keyUsage.length && keyUsage[i];

    }

    public static boolean[] keyUsageFromInt(int keyUsage) {
        String value = "";
        boolean[] booloKu = new boolean[]{false, false, false, false, false, false, false, false, false};
        boolean isKeyUsage = false;

        for (KeyUsageEnum usage : KeyUsageEnum.values()) {
            if ((keyUsage & usage.getIntValue()) == usage.getIntValue()) {
                for (int i = 0; i < X509Constants.keyUsageInt.length; i++) {
                    if (X509Constants.keyUsageInt[i] == usage.getIntValue()) {
                        booloKu[i] = true;
                    }
                }
            }
        }
        return booloKu;

    }
}
