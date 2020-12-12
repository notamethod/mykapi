package org.dpr.mykeys.app;

import org.dpr.mykeys.app.certificate.CryptoObject;

import java.security.PrivateKey;


public class PrivateKeyValue implements CryptoObject {
    private PrivateKey privateKey;

    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    public void setPrivateKey(PrivateKey privateKey) {
        this.privateKey = privateKey;
    }

    public PrivateKeyValue(PrivateKey privateKey) {
    }
}
