package com.notamethod.mkcore.utils;

import org.bouncycastle.asn1.x509.KeyUsage;

public enum KeyUsageEnum {
    cRLSign(KeyUsage.cRLSign, "cRLSign"), digitalSignature(KeyUsage.digitalSignature, //NOSONAR
            "digitalSignature"), nonRepudiation(KeyUsage.nonRepudiation, "nonRepudiation"), keyEncipherment(//NOSONAR
            KeyUsage.keyEncipherment, "keyEncipherment"), dataEncipherment(KeyUsage.dataEncipherment,//NOSONAR
            "dataEncipherment"), keyAgreement(KeyUsage.keyAgreement, "keyAgreement"), keyCertSign(//NOSONAR
            KeyUsage.keyCertSign, "keyCertSign"), encipherOnly(KeyUsage.encipherOnly,//NOSONAR
            "encipherOnly"), decipherOnly(KeyUsage.decipherOnly, "decipherOnly");   //NOSONAR

    private final int intValue;
    private final String label;

    KeyUsageEnum(int value, String strValue) {
        intValue = value;
        label = strValue;
    }

    public int getIntValue() {
        return intValue;
    }

    public String getLabel() {
        return label;
    }

}
