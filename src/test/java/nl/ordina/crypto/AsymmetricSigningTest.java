package nl.ordina.crypto;

import nl.ordina.crypto.util.Utils;
import org.junit.Test;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;

import static org.junit.Assert.assertTrue;

public class AsymmetricSigningTest {

    @Test
    public void testSymmetricSigningEasy() throws GeneralSecurityException {
        // Add BouncyCastle to security providers.
        Utils.loadProvider();

        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA");
        kpGen.initialize(1024);
        KeyPair keyPair = kpGen.generateKeyPair();

        String data = "Hello Fokus!!!";

        // create signature
        Signature signatureAlgorithm = Signature.getInstance("SHA256WithRSA");
        signatureAlgorithm.initSign(keyPair.getPrivate());
        signatureAlgorithm.update(data.getBytes());
        byte[] signature = signatureAlgorithm.sign();

        System.out.println("signature: " + Utils.byteArrayToHexString(signature));
        System.out.println("signature length: " + signature.length);


        // validation of signature
        Signature verificationAlgorithm = Signature.getInstance("SHA256WithRSA");
        verificationAlgorithm.initVerify(keyPair.getPublic());
        verificationAlgorithm.update(data.getBytes());
        boolean matches = verificationAlgorithm.verify(signature);
        assertTrue(matches);

    }
}
