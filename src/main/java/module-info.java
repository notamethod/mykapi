module mkcore {
    requires org.bouncycastle.provider;
    requires org.jetbrains.annotations;
    requires org.bouncycastle.pkix;
    requires org.apache.logging.log4j;
    requires static lombok;
    requires org.apache.commons.io;

    exports com.notamethod.mkcore.keystore.repository;
    exports com.notamethod.mkcore.keystore.repository2;
    exports com.notamethod.mkcore.certificate;
    exports com.notamethod.mkcore.certificate.profile;
    exports com.notamethod.mkcore.keystore;
    exports com.notamethod.mkcore.utils;
    exports com.notamethod.mkcore.common;
    exports com.notamethod.mkcore.crl;
}