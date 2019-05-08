package nl.craftsmen.crypto.util;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.x509.X509V1CertificateGenerator;
import org.bouncycastle.x509.X509V3CertificateGenerator;
import org.bouncycastle.x509.extension.AuthorityKeyIdentifierStructure;

import javax.security.auth.x500.X500Principal;
import javax.security.auth.x500.X500PrivateCredential;
import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Date;

/**
 * Helper class to generate an in-memory keystore filled with sample keys and
 * certificates for health checking.
 */
public final class SampleKeyStoreFactory {

    /**
     * Logger.
     */
    private static final Logger LOG = LogManager.getLogger(SampleKeyStoreFactory.class);

    /**
     * root cert alias for looking up the certificate in the keystore.
     */
    public static final String ROOT_ALIAS = "root";

    /**
     * intermediate cert alias for looking up the certificate in the keystore.
     */
    public static final String INTERMEDIATE_ALIAS = "intermediate";

    /**
     * Certificate key alias for looking up the edn certificate in the keystore.
     */
    public static final String END_ENTITY_ALIAS = "end";

    /**
     * Private key alias for looking up the key in the keystore.
     */
    public static final String PRIVATE_KEY_ALIAS = "privateKey";

    /**
     * Secret key alias for looking up the key in the keystore.
     */
    public static final String SECRET_KEY_ALIAS = "secretKeyAlias";

    /**
     * HMAC key alias for looking up the key in the keystore.
     */
    public static final String HMAC_KEY_ALIAS = "hmacKeyAlias";

    /**
     * AES key alias for looking up the key in the keystore.
     */
    public static final String AES_KEY_ALIAS = "aesKeyAlias";

    /**
     * 3DES key alias for looking up the key in the keystore.
     */
    public static final String TDES_KEY_ALIAS = "tdesKeyAlias";

    /**
     * Pregenerated 3DES key for use in testing.
     */
    public static final String HARD_TRIPLEDES_KEY = "bfE4QzSkV7lk2q3Lm8deCAuoq39bm5vW";

    /**
     * 3DES key alias for looking up the hard 3des key in the keystore.
     */
    public static final String SECRET_KEY_ALIAS_HARD = "secretKeyAliasHard";

    /**
     * Serial number to give to the certificates.
     */
    private static final int SERIAL_NUMBER = 5;

    /**
     * Provider to use. Default is BouncyCastle (BC).
     */
    private String provider = "BC";

    /**
     * Keystore type to generate. Default is JCEKS, which can also hold secret
     * key entries, whereas JKS cannot.
     */
    private String keyStoreType = "JCEKS";

    /**
     * The generated keystore.
     */
    private KeyStore store = null;

    /**
     * The generated root keystore.
     */
    private KeyStore rootStore = null;

    /**
     * The keystore password. Default is an empty string.
     */
    private String keyPassword = null;

    /**
     * Default signature algorithm when generating certificates.
     */
    private String signatureAlgoritm = "SHA1WithRSAEncryption";

    /**
     * Default AES key size.
     */
    private static final int AES_DEFAULT_KEYSIZE = 128;

    /**
     * Default 3DES key size.
     */
    private static final int TDES_DEFAULT_KEYSIZE = 192;

    /**
     * Default RSA key size.
     */
    private static final int RSA_DEFAULT_KEYSIZE = 1024;

    /**
     * AES key size.
     */
    private int aesKeySize = AES_DEFAULT_KEYSIZE;

    /**
     * 3DES key size.
     */
    private int tdesKeySize = TDES_DEFAULT_KEYSIZE;

    /**
     * Give each test certificate a validity of 10 years.
     */
    private static final int VALID_YEARS = 10;

    /**
     * Validity of the certificates. Default is forever.
     */
    private long validUntil = 0;

    /**
     * Constructs a new HealthCheckKeyStoreFactory. The default is a key factory
     * in software.
     */
    public SampleKeyStoreFactory() {

        // setup validty of certificates
        Calendar cal = Calendar.getInstance();
        // set validty of certificates 10 years
        cal.roll(Calendar.YEAR, VALID_YEARS);
        validUntil = cal.getTimeInMillis();
        keyPassword = "";
    }

    /**
     * Gets the generated keystore.
     *
     * @return the keystore.
     */
    public KeyStore getRootKeyStore() {
        if (rootStore == null) {
            createCredentials();
        }
        return rootStore;
    }

    /**
     * Gets the generated keystore.
     *
     * @return the keystore.
     */
    public KeyStore getKeyStore() {
        if (store == null) {
            createCredentials();
        }
        return store;
    }

    /**
     * Create a KeyStore containing the a private credential with certificate
     * chain and a trust anchor.
     */
    private void createCredentials() {
        try {

            LOG.info("Using provider '" + provider + "' to generate in-memory keys and certificates.");
            LOG.info("Generating keystore of type: " + keyStoreType);
            rootStore = KeyStore.getInstance(keyStoreType);
            store = KeyStore.getInstance(keyStoreType);
            rootStore.load(null, keyPassword.toCharArray());
            store.load(null, keyPassword.toCharArray());
            // try {
            // KeyGenerator aesGenerator = KeyGenerator.getInstance("AES",
            // provider);
            // aesGenerator.init(aesKeySize);
            // SecretKey aesKey = aesGenerator.generateKey();
            // store.setKeyEntry(AES_KEY_ALIAS, aesKey,
            // keyPassword.toCharArray(), null);
            // LOG.info("Generated and stored AES key.");
            // } catch (GeneralSecurityException e) {
            // LOG.error("could not generate AES key, perhaps your provider does not support this. Skipping.");
            // }
            //
            // try {
            // KeyGenerator tdesGenerator = KeyGenerator.getInstance("DESEDE",
            // provider);
            // tdesGenerator.init(tdesKeySize);
            // SecretKey tdesKey = tdesGenerator.generateKey();
            // store.setKeyEntry(TDES_KEY_ALIAS, tdesKey,
            // keyPassword.toCharArray(), null);
            // LOG.info("Generated and stored 3DES key.");
            // } catch (GeneralSecurityException e) {
            // LOG.error("could not generate 3DES key, perhaps your provider does not support this. Skipping.");
            // }
            //
            // SecretKeySpec spec = new
            // SecretKeySpec(Base64.decode(HARD_TRIPLEDES_KEY), "DESEDE");
            // LOG.info("Built and stored predefined 3DES key for use as master key for decrypting secret key.");
            // store.setKeyEntry(SECRET_KEY_ALIAS_HARD, spec,
            // keyPassword.toCharArray(), null);
            // try {
            // KeyGenerator g = KeyGenerator.getInstance("HmacSHA256",
            // provider);
            // SecretKey secretKey = g.generateKey();
            // store.setKeyEntry(SECRET_KEY_ALIAS, secretKey,
            // keyPassword.toCharArray(), null);
            // LOG.info("Generated and stored HMACSHA256 key.");
            // } catch (GeneralSecurityException e) {
            // LOG.error("could not generate HMAC key, perhaps your provider does not support this. Skipping.");
            // }
            // String hmacKeyString = "hmac secret key";
            // try {
            // SecretKey hmacKey = new
            // SecretKeySpec(hmacKeyString.getBytes("UTF-8"), "HmacSHA256");
            // store.setKeyEntry(HMAC_KEY_ALIAS, hmacKey,
            // keyPassword.toCharArray(), null);
            // } catch (GeneralSecurityException e) {
            // LOG.error("could not store predefined HMAC key '" + hmacKeyString
            // + "' , perhaps your provider does not support this. Skipping.");
            // }

            X500PrivateCredential rootCredential = createRootCredential();
            X500PrivateCredential interCredential = createIntermediateCredential(rootCredential.getPrivateKey(),
                    rootCredential.getCertificate());
            X500PrivateCredential endCredential = createEndEntityCredential(interCredential.getPrivateKey(),
                    interCredential.getCertificate());
            rootStore.setCertificateEntry(rootCredential.getAlias(), rootCredential.getCertificate());
            store.setCertificateEntry(rootCredential.getAlias(), rootCredential.getCertificate());
            store.setCertificateEntry(interCredential.getAlias(), interCredential.getCertificate());

            // store the public key
            store.setCertificateEntry(endCredential.getAlias(), endCredential.getCertificate());
            LOG.info("Generated and stored certificate.");

            // store the private key
            store.setKeyEntry(PRIVATE_KEY_ALIAS, endCredential.getPrivateKey(), keyPassword.toCharArray(),

                    new Certificate[]{endCredential.getCertificate(), interCredential.getCertificate(),
                            rootCredential.getCertificate()});
            LOG.info("Generated and stored private key.");
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Create a random RSA key pair.
     *
     * @return the key pair.
     * @throws GeneralSecurityException if an error occurs.
     */
    public KeyPair generateRSAKeyPair() throws GeneralSecurityException {
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA", provider);

        kpGen.initialize(RSA_DEFAULT_KEYSIZE, new SecureRandom());

        return kpGen.generateKeyPair();
    }

    /**
     * Generate a X500PrivateCredential for the root entity.
     *
     * @return a root certificate.
     * @throws GeneralSecurityException if an error occurs.
     */
    public X500PrivateCredential createRootCredential() throws GeneralSecurityException {
        KeyPair rootPair = generateRSAKeyPair();
        X509Certificate rootCert = generateRootCert(rootPair);
        return new X500PrivateCredential(rootCert, rootPair.getPrivate(), ROOT_ALIAS);
    }

    /**
     * Generate a X500PrivateCredential for the intermediate entity.
     *
     * @param caKey  the ca key.
     * @param caCert the caCert.
     * @return an intermediate certificate.
     * @throws GeneralSecurityException if an error occurs.
     */
    public X500PrivateCredential createIntermediateCredential(PrivateKey caKey, X509Certificate caCert)
            throws GeneralSecurityException {
        KeyPair interPair = generateRSAKeyPair();
        X509Certificate interCert = generateIntermediateCert(interPair.getPublic(), caKey, caCert);

        return new X500PrivateCredential(

                interCert, interPair.getPrivate(), INTERMEDIATE_ALIAS);
    }

    /**
     * Generate a sample V1 certificate to use as a CA root certificate.
     *
     * @param pair the keypair to base the certificate on.
     * @return the x509 certificate.
     * @throws GeneralSecurityException if an error occurs during certificate generation.
     */
    public X509Certificate generateRootCert(KeyPair pair) throws GeneralSecurityException {
        X509V1CertificateGenerator certGen = new X509V1CertificateGenerator();
        certGen.setSerialNumber(BigInteger.valueOf(SERIAL_NUMBER));
        certGen.setIssuerDN(new X500Principal("CN=Test CA Certificate"));
        certGen.setNotBefore(new Date());
        certGen.setNotAfter(new Date(validUntil));
        certGen.setSubjectDN(new X500Principal("CN=Test CA Certificate"));
        certGen.setPublicKey(pair.getPublic());
        certGen.setSignatureAlgorithm(signatureAlgoritm);

        return certGen.generate(pair.getPrivate(), provider);
    }

    /**
     * Generate a sample V3 certificate to use as an intermediate CA
     * certificate.
     *
     * @param intKey the private key for this certificate.
     * @param caKey  the public key of the root certificate.
     * @param caCert the root certificate with which to sign the intermediate
     *               certificate.
     * @return the intermediate certificate.
     * @throws GeneralSecurityException if an error occurs during certificate generation.
     */
    public X509Certificate generateIntermediateCert(PublicKey intKey, PrivateKey caKey, X509Certificate caCert)
            throws GeneralSecurityException {
        X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();
        certGen.setSerialNumber(BigInteger.valueOf(SERIAL_NUMBER));
        certGen.setIssuerDN(caCert.getSubjectX500Principal());
        certGen.setNotBefore(new Date());
        certGen.setNotAfter(new Date(validUntil));
        certGen.setSubjectDN(new X500Principal("CN=Test Intermediate Certificate"));
        certGen.setPublicKey(intKey);
        certGen.setSignatureAlgorithm(signatureAlgoritm);
        certGen.addExtension(X509Extensions.AuthorityKeyIdentifier, false, new AuthorityKeyIdentifierStructure(caCert));
//        certGen.addExtension(X509Extensions.SubjectKeyIdentifier, false, new SubjectKeyIdentifierStructure(intKey));
        certGen.addExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(0));
        certGen.addExtension(X509Extensions.KeyUsage, true, new KeyUsage(KeyUsage.digitalSignature
                | KeyUsage.keyCertSign | KeyUsage.cRLSign));

        GeneralName gn = new GeneralName(GeneralName.uniformResourceIdentifier, new DERIA5String(
                "http://test-hsmwin.rabobank.nl/crl/ryptotoolbox.crl"));
        //      GeneralNames gns = new GeneralNames(new DERSequence(gn));
        //    DistributionPointName dpn = new DistributionPointName(0, gns);
        //  DistributionPoint distp = new DistributionPoint(dpn, null, null);
        //certGen.addExtension(X509Extensions.CRLDistributionPoints, false, new DERSequence(distp));
        return certGen.generate(caKey, provider);
    }

    /**
     * Generate a sample V3 certificate to use as an end entity certificate.
     *
     * @param entityKey the private key for this certificate.
     * @param caKey     the public key of the intermediate certificate.
     * @param caCert    the intermediate certificate with which to sign the end entity
     *                  certificate.
     * @return the end entity certificate.
     * @throws GeneralSecurityException if an error occurs during certificate generation.
     */
    public X509Certificate generateEndEntityCert(PublicKey entityKey, PrivateKey caKey, X509Certificate caCert)
            throws GeneralSecurityException {
        X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();

        certGen.setSerialNumber(BigInteger.valueOf(SERIAL_NUMBER));
        certGen.setIssuerDN(caCert.getSubjectX500Principal());
        certGen.setNotBefore(new Date());
        certGen.setNotAfter(new Date(validUntil));
        certGen.setSubjectDN(new X500Principal("CN=Test End Certificate"));
        certGen.setPublicKey(entityKey);
        certGen.setSignatureAlgorithm(signatureAlgoritm);

        certGen.addExtension(X509Extensions.AuthorityKeyIdentifier, false, new AuthorityKeyIdentifierStructure(caCert));
        // certGen.addExtension(X509Extensions.SubjectKeyIdentifier, false, new SubjectKeyIdentifierStructure(entityKey));
        certGen.addExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(false));
        certGen.addExtension(X509Extensions.KeyUsage, true, new KeyUsage(KeyUsage.digitalSignature
                | KeyUsage.keyEncipherment));

        GeneralName gn = new GeneralName(GeneralName.uniformResourceIdentifier, new DERIA5String(
                "http://test-hsmwin.rabobank.nl/crl/ryptotoolbox.crl"));
        //   GeneralNames gns = new GeneralNames(new DERSequence(gn));
        //   DistributionPointName dpn = new DistributionPointName(0, gns);
        //   DistributionPoint distp = new DistributionPoint(dpn, null, null);
        //    certGen.addExtension(X509Extensions.CRLDistributionPoints, false, new DERSequence(distp));

        return certGen.generate(caKey, provider);
    }

    /**
     * Generate a X500PrivateCredential for the end entity.
     *
     * @param caKey  the private key for the end entity certificate.
     * @param caCert the end certificate.
     * @return the credential.
     * @throws GeneralSecurityException if an error occurs.
     */
    public X500PrivateCredential createEndEntityCredential(PrivateKey caKey, X509Certificate caCert)
            throws GeneralSecurityException {
        KeyPair endPair = generateRSAKeyPair();
        X509Certificate endCert = generateEndEntityCert(endPair.getPublic(), caKey, caCert);

        return new X500PrivateCredential(endCert, endPair.getPrivate(), END_ENTITY_ALIAS);
    }

}
