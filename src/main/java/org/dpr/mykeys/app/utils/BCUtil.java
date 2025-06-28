package org.dpr.mykeys.app.utils;


import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.asn1.x509.KeyPurposeId;

import java.util.Map;

public class BCUtil {

    protected static final Logger log = LogManager.getLogger(BCUtil.class);

    private BCUtil(){
       throw new IllegalStateException("Utility class");
    }

    static Map<KeyPurposeId, String> extendedKeyUsages = Map.of(
            KeyPurposeId.id_kp_clientAuth, "eku.clientAuth",
            KeyPurposeId.id_kp_codeSigning, "eku.codeSigning",
            KeyPurposeId.id_kp_serverAuth, "eku.serverAuth");
}
