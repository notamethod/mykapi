package com.notamethod.mkcore.test;

import com.notamethod.mkcore.certificate.CertificateBuilder;
import com.notamethod.mkcore.utils.ProviderUtil;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.security.cert.X509Certificate;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.fail;

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
           fail(e);
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
