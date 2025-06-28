package org.dpr.mykeys.app.keystore;

public enum StoreFormat {
    JKS(".jks"), PKCS12(".p12"), PEM(".crt"), DER(".cer"), UNKNOWN(""), PROPERTIES("");

    private final String extension;


    StoreFormat(String extension) {
        this.extension = extension;

    }

    public String getExtension() {
        return extension;
    }


	public static StoreFormat fromValue(String v) {
		StoreFormat fmt;
		try {
			fmt = valueOf(v);
		} catch (Exception e) {
			fmt = UNKNOWN;
		}
		return fmt;

	}

	public static String getValue(StoreFormat format) {
		return format.toString();
	}

}