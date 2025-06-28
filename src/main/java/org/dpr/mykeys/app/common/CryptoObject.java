package org.dpr.mykeys.app.common;

/**
 * to delete if not used
 */
public interface CryptoObject {
    byte[] getEncoded();

    enum Type{
        CERTIFICATE, PRIVATE_KEY
    }
    Type getType();

    char[] getPassword();

    String getHumanIdentifier();
}
