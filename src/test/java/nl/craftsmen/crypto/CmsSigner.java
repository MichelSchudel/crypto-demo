package nl.craftsmen.crypto;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.cert.CertStore;
import java.security.cert.Certificate;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;

import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureInterface;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessable;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

public class CmsSigner implements SignatureInterface {

    private Provider provider;

    private PrivateKey privKey;

    private Certificate[] cert;

    public CmsSigner(Provider provider, PrivateKey privateKey, Certificate[] certificates) {
        this.privKey = privateKey;
        this.cert = certificates;
        this.provider = provider;
    }
    @Override
    public byte[] sign(InputStream content) throws IOException {
        CMSProcessableInputStream input = new CMSProcessableInputStream(content);
        CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
        // CertificateChain
        List<Certificate> certList = Arrays.asList(cert);

        Security.addProvider(provider);

        CertStore certStore = null;
        try {
            certStore = CertStore.getInstance("Collection", new CollectionCertStoreParameters(certList), provider);
            ContentSigner sha256Signer = new JcaContentSignerBuilder("SHA256withRSA").setProvider(BouncyCastleProvider.PROVIDER_NAME)
                    .build(privKey);

            JcaCertStore jcaCertStore = new JcaCertStore(certList);
            gen.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().setProvider(BouncyCastleProvider.PROVIDER_NAME)
                    .build()).build(sha256Signer, (X509Certificate) certList.get(0)));
            gen.addCertificates(jcaCertStore);
            gen.addCRLs(jcaCertStore);

            CMSTypedData chainMessage = new CMSProcessableByteArray(content.readAllBytes());
            CMSSignedData signedData = gen.generate(chainMessage);

            return signedData.getEncoded();
        } catch (Exception e) {
            // should be handled
            e.printStackTrace();
        }
        throw new RuntimeException("Problem while preparing signature");
    }
}
class CMSProcessableInputStream implements CMSProcessable {

    InputStream in;

    public CMSProcessableInputStream(InputStream is) {
        in = is;
    }

    public Object getContent() {
        return null;
    }

    public void write(OutputStream out) throws IOException, CMSException {
        // read the content only one time
        byte[] buffer = new byte[8 * 1024];
        int read;
        while ((read = in.read(buffer)) != -1) {
            out.write(buffer, 0, read);
        }
        in.close();
    }
}
