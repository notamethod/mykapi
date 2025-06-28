package org.dpr.mykeys.app.common;

import org.dpr.mykeys.app.common.CryptoObject;

import java.security.PrivateKey;


public class PrivateKeyValue implements CryptoObject {
    private PrivateKey privateKey;
    private String envelop;
    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    public void setPrivateKey(PrivateKey privateKey) {
        this.privateKey = privateKey;
    }

    public PrivateKeyValue(PrivateKey privateKey) {
        this.privateKey = privateKey;
    }

    @Override
    public byte[] getEncoded() {
        return privateKey.getEncoded();
    }

    @Override
    public Type getType() {
        return Type.PRIVATE_KEY;
    }

    @Override
    public char[] getPassword() {
        return new char[0];
    }

    @Override
    public String getHumanIdentifier() {
        return privateKey.getFormat();
    }

    public void setEnvelop(String pkcs8) {
        this.envelop=pkcs8;
    }
}
