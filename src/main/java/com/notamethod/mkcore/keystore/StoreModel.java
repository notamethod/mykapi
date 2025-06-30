package com.notamethod.mkcore.keystore;

public enum StoreModel {
	CASTORE, CERTSTORE, KEYSTORE, P12STORE, PROFILSTORE, PKISTORE;

	public static StoreModel fromValue(String v) {
		return valueOf(v);
	}

	public static String getValue(StoreModel type) {
		return type.toString();
	}
}