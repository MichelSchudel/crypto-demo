package nl.craftsmen.crypto;

import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcContentSignerBuilder;
import org.bouncycastle.operator.bc.BcRSAContentSignerBuilder;
import org.junit.Test;

import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.*;

public class KeystoreTest {


    @Test
    public void createKeyStore() throws GeneralSecurityException, IOException, OperatorCreationException {
        if (Files.exists(Path.of("myStore.pkcs12"))) {
            Files.delete(Path.of("myStore.pkcs12"));
        }
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(null, null);
        //create keypair
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();
        Key pub = kp.getPublic();
        Key pvt = kp.getPrivate();
        X509Certificate x509Certificate = generateRootCert(kp);
        keyStore.setCertificateEntry("myRootCertificate", x509Certificate);
        Certificate[] chain = {x509Certificate};
        keyStore.setKeyEntry("myPrivateKey", pvt, "password".toCharArray(), chain);
        keyStore.store(new FileOutputStream("myStore.pkcs12"), "password".toCharArray());
        Enumeration<String> enums = keyStore.aliases();
        System.out.println("aliases:");
        enums.asIterator().forEachRemaining(System.out::println);
        Key key = keyStore.getKey("myPrivateKey", "password".toCharArray());
        System.out.println(key.toString());
        Certificate certificate = keyStore.getCertificate("myRootCertificate");
        System.out.println(certificate.toString());
    }

    public X509Certificate generateRootCert(KeyPair pair) throws IOException, OperatorCreationException, CertificateException {
        Calendar expiry = Calendar.getInstance();
        expiry.add(Calendar.DAY_OF_YEAR, 365);

        //final GeneralNames subjectAltNames = new GeneralNames(new GeneralName(GeneralName.iPAddress, "127.0.0.1"));
        //certificateBuilder.addExtension(org.bouncycastle.asn1.x509.Extension.subjectAlternativeName, false, subjectAltNames);

        AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(PKCSObjectIdentifiers.sha256WithRSAEncryption);
        AlgorithmIdentifier sigAlgId = new AlgorithmIdentifier(algorithmIdentifier.getAlgorithm(), DERNull.INSTANCE);
        final AlgorithmIdentifier digAlgId = new DefaultDigestAlgorithmIdentifierFinder().find(sigAlgId);
        final BcContentSignerBuilder signerBuilder = new BcRSAContentSignerBuilder(sigAlgId, digAlgId);
        final AsymmetricKeyParameter keyp = PrivateKeyFactory.createKey(pair.getPrivate().getEncoded());
        final ContentSigner signer = signerBuilder.build(keyp);

        X509v3CertificateBuilder x509v3CertificateBuilder = new X509v3CertificateBuilder(
                new X500Name("CN=Root Certificate"),
                BigInteger.ONE,
                new Date(),
                expiry.getTime(),
                Locale.ENGLISH,
                new X500Name("CN=Root Certificate"),
                SubjectPublicKeyInfo.getInstance(pair.getPublic().getEncoded())
        );
        final X509CertificateHolder x509CertificateHolder = x509v3CertificateBuilder.build(signer);
        final X509Certificate certificate = new JcaX509CertificateConverter()
                .getCertificate(x509CertificateHolder);
        return certificate;
    }
}
