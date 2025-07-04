package com.notamethod.mkcore.certificate;

import org.bouncycastle.cert.X509v3CertificateBuilder;

import java.io.IOException;
import java.util.Map;

@FunctionalInterface
public interface CertificateGeneratorExtensions {

    void addExtensions(X509v3CertificateBuilder certGen, Map<String, String> parameters) throws IOException;

}
