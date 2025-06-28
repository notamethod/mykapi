package org.dpr.mykeys.app.certificate;

public enum CertificateType {
    STANDARD, AC, SERVER, CODE_SIGNING, AUTH;
	public static CertificateType fromValue(String v) {
		return valueOf(v);
	}

	public static String getValue(CertificateType type) {
		return type.toString();
	}
}