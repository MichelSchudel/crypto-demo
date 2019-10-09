package nl.craftsmen.crypto;

import java.io.ByteArrayInputStream;
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
import java.security.Provider;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertPathValidator;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
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

    private static Provider provider = new BouncyCastleProvider();

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
        //File signedFile = new File("test_uwv_pdf.pdf");
        File signedFile = new File("signed.pdf");
        //File signedFile = new File("pdf_digital_signature_timestamp.pdf");
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
            Collection<SignerInformation> signerInformationList = signerInformationStore.getSigners();
            Store<X509CertificateHolder> certificateHolderStore = cmsSignedData.getCertificates();
            Store<X509CRLHolder> crlHolderStore = cmsSignedData.getCRLs();
            Iterator<SignerInformation> signerInformationIterator = signerInformationList.iterator();
            while (signerInformationIterator.hasNext()) {
                SignerInformation signerInformation = signerInformationIterator.next();
                Collection<X509CertificateHolder> certificateHolders = certificateHolderStore.getMatches(signerInformation.getSID());
                Iterator<X509CertificateHolder> certificateHolderIterator = certificateHolders.iterator();
                X509CertificateHolder signerCertificate = certificateHolderIterator.next();
                // And here we validate the document signature.
                SignerInformationVerifier siv = new JcaSimpleSignerInfoVerifierBuilder().setProvider(provider)
                        .build(signerCertificate);

                //alternate
//                CertificateFactory certificateFactory = CertificateFactory.getInstance("X509");
//                Certificate certificate = certificateFactory.generateCertificate(new ByteArrayInputStream(signerCertificate.getEncoded()));
//
//                Signature signature = Signature.getInstance("SHA256withRSA", provider);
//                signature.initVerify(certificate.getPublicKey());
//                signature.update(signedContent);

//                boolean result = signature.verify(signerInformation.getSignature());

//                System.out.println(result);

                if (signerInformation.verify(siv)) {
                    System.out.println("PDF signature verification is correct.");
                    // IMPORTANT: Note that you should usually validate the signing certificate in this phase, e.g. trust, validity, revocation, etc. See http://www.nakov.com/blog/2009/12/01/x509-certificate-validation-in-java-build-and-verify-chain-and-verify-clr-with-bouncy-castle/.
                    CertPathValidator certPathValidator = CertPathValidator.getInstance("PKIX");
                } else {
                    System.out.println("PDF signature verification failed.");
                }
            }
        }
    }

    static void addSignature(PDDocument pdDocument, String filePath, String pwd) throws Exception {
        File ksFile = new File(filePath);
        KeyStore keystore = KeyStore.getInstance("PKCS12");
        char[] pin = pwd.toCharArray();
        keystore.load(new FileInputStream(ksFile), pin);
        loadKeystore(keystore, pin);
        CmsSigner cmsSigner = new CmsSigner(provider, privKey, cert);
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

