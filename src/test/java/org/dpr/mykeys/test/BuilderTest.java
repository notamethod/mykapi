package org.dpr.mykeys.test;

import org.dpr.mykeys.app.certificate.CertificateBuilder;
import org.dpr.mykeys.app.utils.ProviderUtil;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.security.cert.X509Certificate;

import static org.junit.jupiter.api.Assertions.assertNotNull;

public class BuilderTest {

    @BeforeAll
    public static void init() {
        ProviderUtil.initBC();
    }
    @Test
    public void test_all_is_ok(){
        CertificateBuilder builder = new CertificateBuilder();
        X509Certificate builded = null;
        try {
            builded= builder.build();
        } catch (Exception e) {
            e.printStackTrace();
        }
        assertNotNull(builded);
    }

    @Test
    public void test_options(){
        CertificateBuilder builder = new CertificateBuilder();
        X509Certificate builded = null;
        try {
            builded= builder.
                    withSubject("O=AA").
                    build();
        } catch (Exception e) {
            e.printStackTrace();
        }
        assertNotNull(builded);
    }
}
