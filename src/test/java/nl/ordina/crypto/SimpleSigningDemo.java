package nl.ordina.crypto;

import nl.ordina.crypto.util.Utils;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.junit.Test;

import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

public class SimpleSigningDemo {

    @Test
    public void testAsymmetricSigningWithSignatureClasses() throws GeneralSecurityException, DecoderException {

        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA");
        kpGen.initialize(1024);
        KeyPair keyPair = kpGen.generateKeyPair();
        Utils.printByteArray("private key", keyPair.getPrivate().getEncoded());
        Utils.printByteArray("public key", keyPair.getPublic().getEncoded());

        String data = "JFokus is the best!!!";

        // create signature
        Signature signatureAlgorithm = Signature.getInstance("SHA256WithRSA");
        signatureAlgorithm.initSign(keyPair.getPrivate());
        signatureAlgorithm.update(data.getBytes());
        byte[] signature = signatureAlgorithm.sign();
        Utils.printByteArray("signature", signature);

        Signature verificationAlgorithm = Signature.getInstance("SHA256WithRSA");
        verificationAlgorithm.initVerify(keyPair.getPublic());
        verificationAlgorithm.update(data.getBytes());
        boolean matches = verificationAlgorithm.verify(signature);
        System.out.println("signature matches: " + matches);

    }

}
