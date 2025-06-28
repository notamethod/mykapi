package org.dpr.mykeys.app.keystore;



import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.dpr.mykeys.app.common.CryptoObject;
import org.dpr.mykeys.app.utils.NestedExceptionUtils;
import org.dpr.mykeys.app.keystore.repository.MkKeystore;
import org.dpr.mykeys.app.keystore.repository.PemKeystoreRepository;
import org.dpr.mykeys.app.keystore.repository.RepositoryException;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.UnrecoverableKeyException;
import java.util.List;

public class KeystoreUtils {
    public static final String KSTYPE_EXT_JKS = "jks";
    public static final String KSTYPE_EXT_P12 = "p12";
    private static final String[] KSTYPE_EXTS_PKCS12 = {"p12", "pfx", "pkcs12"};
    private static final String[] KSTYPE_EXTS_DER = {"der", "cer"};
    private static final String[] KSTYPE_EXT_PEM = {"pem", "crt"};

    private static final Logger log = LogManager.getLogger(KeystoreUtils.class);

    public static StoreFormat findKeystoreType(String filename) throws UnknownKeystoreTypeException {
        StoreFormat format = KeystoreUtils.findKeystoreTypeByExtension(filename);
        if (StoreFormat.UNKNOWN.equals(format) && Files.exists(Paths.get(filename))) {
            format= findKeystoreTypeByContent(filename);
            if (StoreFormat.UNKNOWN.equals(format)){
                throw new UnknownKeystoreTypeException("Keystore type unknown: "+filename);
            }
        }

        return format;

    }

    public static StoreFormat findKeystoreTypeByExtension(String filename) {

        log.debug("finding type of file...");
        try {
            String ext = filename.substring(filename.lastIndexOf('.') + 1);
            if (ext.equalsIgnoreCase(KSTYPE_EXT_JKS)) {
                return StoreFormat.JKS;
            }
            for (String aliasType : KSTYPE_EXTS_PKCS12) {
                if (ext.equalsIgnoreCase(aliasType)) {
                    return StoreFormat.PKCS12;
                }
            }
            for (String aliasType : KSTYPE_EXTS_DER) {
                if (ext.equalsIgnoreCase(aliasType)) {
                    return StoreFormat.DER;
                }
            }
            for (String aliasType : KSTYPE_EXT_PEM) {
                if (ext.equalsIgnoreCase(aliasType)) {
                    return StoreFormat.PEM;
                }
            }

            return StoreFormat.UNKNOWN;
        } catch (IndexOutOfBoundsException e) {
            return StoreFormat.UNKNOWN;
        }
    }

    public static StoreFormat findKeystoreTypeByContent(String filename) {
        log.debug("finding type of file...");
        MkKeystore mkKeystore = MkKeystore.getInstance(StoreFormat.JKS);
        try {
            mkKeystore.load(filename, "".toCharArray());
        } catch (RepositoryException e) {
            if (NestedExceptionUtils.getMostSpecificCause(e) instanceof UnrecoverableKeyException
                    && e.getMessage().contains("Password verification failed")) {
                System.out.println("key");
                return StoreFormat.JKS;
            }
        }
        mkKeystore = MkKeystore.getInstance(StoreFormat.PKCS12);
        try {
            mkKeystore.load(filename, "".toCharArray());
        } catch (RepositoryException e) {
            Throwable rootException = NestedExceptionUtils.getMostSpecificCause(e);
            if (rootException instanceof IOException
                    && rootException.getMessage().contains("wrong password") && rootException.getMessage().contains("PKCS12")) {
                return StoreFormat.PKCS12;
            }
        }
        mkKeystore = MkKeystore.getInstance(StoreFormat.PEM);
        try {
            MKKeystoreValue storeValue = mkKeystore.load(filename, "".toCharArray());
            List<CryptoObject> objects = ((PemKeystoreRepository) mkKeystore).getElements(storeValue);
            if (objects != null && !objects.isEmpty())
                return StoreFormat.PEM;
        } catch (RepositoryException e) {
            e.printStackTrace();

        }
        return StoreFormat.UNKNOWN;
    }
}
