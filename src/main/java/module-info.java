module mykapi {
    requires org.bouncycastle.provider;
    requires org.jetbrains.annotations;
    requires org.bouncycastle.pkix;
    requires org.apache.logging.log4j;
    requires static lombok;
    requires org.apache.commons.io;

    exports org.dpr.mykeys.app.keystore.repository;
    exports org.dpr.mykeys.app.keystore.repository2;
    exports org.dpr.mykeys.app.certificate;
    exports org.dpr.mykeys.app.certificate.profile;
    exports org.dpr.mykeys.app.keystore;
    exports org.dpr.mykeys.app.utils;
    exports org.dpr.mykeys.app.common;
    exports org.dpr.mykeys.app.crl;
}