package nl.craftsmen.crypto;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.Assert.assertTrue;

import nl.craftsmen.crypto.util.Utils;
import org.apache.commons.codec.DecoderException;
import org.junit.Test;

import java.security.*;

public class SimpleSigningDemo {

    @Test
    public void testAsymmetricSigningWithSignatureClasses() throws GeneralSecurityException, DecoderException {

        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA");
        kpGen.initialize(1024);
        KeyPair keyPair = kpGen.generateKeyPair();
        Utils.printByteArray("private key", keyPair.getPrivate().getEncoded());
        Utils.printByteArray("public key", keyPair.getPublic().getEncoded());

        String data = "Devoxx is the best!!!";

        Signature signatureAlgorithm = Signature.getInstance("SHA256WithRSA");
        signatureAlgorithm.initSign(keyPair.getPrivate());
        signatureAlgorithm.update(data.getBytes());

        byte[] signature = signatureAlgorithm.sign();

        Utils.printByteArray("signature", signature);



        //verification on the other end
        String receivedData = "Devoxx is the worst!!!";

        Signature verificationAlgorithm = Signature.getInstance("SHA256WithRSA");
        verificationAlgorithm.initVerify(keyPair.getPublic());
        verificationAlgorithm.update(receivedData.getBytes());

        boolean matches = verificationAlgorithm.verify(signature);

        System.out.println("signature matches: " + matches);
        assertThat(matches).isTrue();
    }

}
