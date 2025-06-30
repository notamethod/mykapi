package com.notamethod.mkcore.keystore;


public enum PEMType {
    CERTIFICATE("-----BEGIN CERTIFICATE-----","-----END CERTIFICATE-----"),
    REQUEST("-----BEGIN CERTIFICATE REQUEST-----", "-----END CERTIFICATE REQUEST-----"),
    PRIVATE_KEY("-----BEGIN PRIVATE KEY-----", "-----END PRIVATE KEY-----"),
    PRIVATE_RSAKEY("-----BEGIN RSA PRIVATE KEY-----", "-----END RSA PRIVATE KEY-----"),
    PUBLIC_KEY("-----BEGIN PUBLIC KEY-----", "-----END PUBLIC KEY-----"),
    ATTRIBUTE_CERTIFICATE("-----BEGIN ATTRIBUTE CERTIFICATE-----", "-----END ATTRIBUTE CERTIFICATE-----"),
    CMS("-----BEGIN CMS-----", "-----END CMS-----"),
    PKCS7("-----BEGIN PKCS7-----", "-----END PKCS7-----"),
    ENCRYPTED_PRIVATE_KEY("-----BEGIN ENCRYPTED PRIVATE KEY-----", "-----END ENCRYPTED PRIVATE KEY-----");

    private final String begin;
    private final String end;
//    private final String bcType;

    PEMType(String begin, String end) {
        this.begin=begin;
        this.end=end;
    }

    public String Begin(){
        return begin;
    }

    public String End(){
        return end;
    }

//    public static PEMType fromBCType(String text) {
//        for (PEMType b : PEMType.values()) {
//            if (b.text.equalsIgnoreCase(text)) {
//                return b;
//            }
//        }
//        return null;
//    }
}
