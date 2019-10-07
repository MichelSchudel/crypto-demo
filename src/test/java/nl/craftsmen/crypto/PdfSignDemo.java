package nl.craftsmen.crypto;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Collection;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.List;

import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSProcessable;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.SignerInformationVerifier;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Store;

public class PdfSignDemo {

    private static BouncyCastleProvider provider = new BouncyCastleProvider();

    private static PrivateKey privKey;

    private static Certificate[] cert;

    public static void main(String[] args)
            throws KeyStoreException, NoSuchAlgorithmException, CertificateException, FileNotFoundException, IOException, SignatureException, Exception {

        InputStream documentStream = PdfSignDemo.class.getResourceAsStream("/sample.pdf");
        PDDocument pdDocument = PDDocument.load(documentStream);

        final String filePath = PdfSignDemo.class.getResource("/keystore.p12")
                .getFile();

        addSignature(pdDocument, filePath, "password");
        FileOutputStream fos = new FileOutputStream("signed.pdf");
        pdDocument.saveIncremental(fos);
        pdDocument.close();

        verifySignature();
    }

    public static void verifySignature() throws Exception {
        File signedFile = new File("signed.pdf");
        // We load the signed document.
        PDDocument document = PDDocument.load(signedFile);
        List<PDSignature> signatureDictionaries = document.getSignatureDictionaries();
        // Then we validate signatures one at the time.
        for (PDSignature signatureDictionary : signatureDictionaries) {
            // NOTE that this code currently supports only "adbe.pkcs7.detached", the most common signature /SubFilter anyway.
            byte[] signatureContent = signatureDictionary.getContents(new FileInputStream(signedFile));
            byte[] signedContent = signatureDictionary.getSignedContent(new FileInputStream(signedFile));
            // Now we construct a PKCS #7 or CMS.
            CMSProcessable cmsProcessableInputStream = new CMSProcessableByteArray(signedContent);
            CMSSignedData cmsSignedData = new CMSSignedData(cmsProcessableInputStream, signatureContent);
            SignerInformationStore signerInformationStore = cmsSignedData.getSignerInfos();
            Collection<SignerInformation> signers = signerInformationStore.getSigners();
            Store<X509CertificateHolder> certs = cmsSignedData.getCertificates();
            Store<X509CRLHolder> crls = cmsSignedData.getCRLs();
            Iterator<SignerInformation> signersIterator = signers.iterator();
            while (signersIterator.hasNext()) {
                SignerInformation signerInformation = signersIterator.next();
                Collection<X509CertificateHolder> certificates = certs.getMatches(signerInformation.getSID());
                Iterator<X509CertificateHolder> certIt = certificates.iterator();
                X509CertificateHolder signerCertificate = certIt.next();
                // And here we validate the document signature.
                SignerInformationVerifier siv = new JcaSimpleSignerInfoVerifierBuilder().setProvider(provider).build(signerCertificate);

                if (signerInformation.verify(siv)) {
                    System.out.println("PDF signature verification is correct.");
                    // IMPORTANT: Note that you should usually validate the signing certificate in this phase, e.g. trust, validity, revocation, etc. See http://www.nakov.com/blog/2009/12/01/x509-certificate-validation-in-java-build-and-verify-chain-and-verify-clr-with-bouncy-castle/.
                } else {
                    System.out.println("PDF signature verification failed.");
                }
            }
        }
    }

    static void addSignature(PDDocument pdDocument, String filePath, String pwd) throws Exception {
        File ksFile = new File(filePath);
        KeyStore keystore = KeyStore.getInstance("PKCS12", provider);
        char[] pin = pwd.toCharArray();
        keystore.load(new FileInputStream(ksFile), pin);
        loadKeystore(keystore, pin);
        CmsSigner cmsSigner = new CmsSigner(new BouncyCastleProvider(), privKey, cert);
        //signing.signPDF(document);

        // create signature dictionary
        PDSignature pdSignature = new PDSignature();
        pdSignature.setFilter(PDSignature.FILTER_ADOBE_PPKLITE); // default filter
        // subfilter for basic and PAdES Part 2 signatures
        pdSignature.setSubFilter(PDSignature.SUBFILTER_ADBE_PKCS7_DETACHED);
        pdSignature.setName("signer name");
        pdSignature.setLocation("signer location");
        pdSignature.setReason("reason for signature");

        // the signing date, needed for valid signature
        pdSignature.setSignDate(Calendar.getInstance());
        //      SignatureOptions signatureOptions= new SignatureOptions();
        //      signatureOptions.setVisualSignature();
        // register signature dictionary and sign interface
        pdDocument.addSignature(pdSignature, cmsSigner);

    }

    static void loadKeystore(KeyStore keystore, char[] pin) throws KeyStoreException, NoSuchAlgorithmException {
        try {
            Enumeration<String> aliases = keystore.aliases();
            String alias = null;
            if (aliases.hasMoreElements()) {
                alias = aliases.nextElement();
            } else {
                throw new RuntimeException("Could not find Key");
            }
            privKey = (PrivateKey) keystore.getKey(alias, pin);
            cert = keystore.getCertificateChain(alias);
        } catch (KeyStoreException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (UnrecoverableKeyException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
    }

}

