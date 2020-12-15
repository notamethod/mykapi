package org.dpr.mykeys.app;

/**
 * to delete if not used
 */
public interface CryptoObject {
    byte[] getEncoded();

    public enum Type{
        CERTIFICATE, PRIVATE_KEY;
    }
    Type getType();

    char[] getPassword();

    String getHumanIdentifier();
}
