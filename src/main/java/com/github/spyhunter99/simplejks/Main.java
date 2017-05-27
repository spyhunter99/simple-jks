package com.github.spyhunter99.simplejks;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import sun.security.x509.*;
import java.security.cert.*;
import java.security.*;
import java.util.Date;
import java.io.FileOutputStream;
import sun.misc.BASE64Encoder;
import sun.security.provider.X509Factory;
import sun.security.tools.keytool.CertAndKeyGen;

/**
 *
 * @author AO
 */
public class Main {

    public static void main(String[] args) throws Exception {
        new Main().generate("CN=test,O=gina");
    }

    public void generate(String dname) throws Exception {
        int keysize = 1024;

        String alias = "server";

        KeyStore keyStore = KeyStore.getInstance("JKS");
        keyStore.load(null, "pass".toCharArray());

        String sigAlgName = "SHA1WithRSA";

        CertAndKeyGen keypair
                = new CertAndKeyGen("RSA", sigAlgName);

        X500Name x500Name = new X500Name(dname);

        keypair.generate(keysize);
        PrivateKey privKey = keypair.getPrivateKey();

        X509Certificate[] chain = new X509Certificate[1];
        chain[0] = keypair.getSelfCertificate(
                x500Name, new Date(), 9999 * 24L * 60L * 60L);

        keyStore.setKeyEntry(alias, privKey, "keypass".toCharArray(), chain);

        keyStore.store(new FileOutputStream("keystore.jks"), "keypass".toCharArray());

        //ok now generate a server cert signed by the rootCA
        KeyStore trustStore = KeyStore.getInstance("JKS");
        trustStore.load(null, null);
        trustStore.setCertificateEntry(alias, chain[0]);
        trustStore.store(new FileOutputStream("truststore.jks"), "keypass".toCharArray());

    }
}
