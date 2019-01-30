package nl.ordina.crypto;

import nl.ordina.crypto.util.Utils;
import org.junit.Test;

import javax.crypto.Cipher;
import java.security.*;

import static org.junit.Assert.assertTrue;

public class SigntatureDemo {

    @Test
    public void testAsymmetricSigningHard() throws GeneralSecurityException {
        // Add BouncyCastle to security providers.
        Utils.loadProvider();

        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA");
        kpGen.initialize(1024);
        KeyPair keyPair = kpGen.generateKeyPair();

        String data = "Hello Fokus!!!";

        MessageDigest digester = MessageDigest.getInstance("SHA-256");

        byte[] digest = digester.digest(data.getBytes());

        //create signature
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPrivate());

        byte[] signature = cipher.doFinal(digest);

        System.out.println("signature: " + Utils.byteArrayToHexString(signature));
        System.out.println("signature length: " + signature.length);


        // validation of signature
        cipher.init(Cipher.DECRYPT_MODE, keyPair.getPublic());
        byte[] decryptedDigest = cipher.doFinal(signature);
        byte[] calculatedDigest =  digester.digest(data.getBytes());
        System.out.println("decryptedDigest: " + Utils.byteArrayToHexString(decryptedDigest));
        System.out.println("calculatedDigest: " + Utils.byteArrayToHexString(calculatedDigest));


    }

    @Test
    public void testAsymmetricSigningWithSignatureClasses() throws GeneralSecurityException {
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
