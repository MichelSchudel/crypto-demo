package nl.ordina.crypto;

import nl.ordina.crypto.util.Utils;
import org.junit.Test;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;

import static org.junit.Assert.assertEquals;

public class HMACDemo {

    @Test
    public void testHMac() throws NoSuchAlgorithmException, InvalidKeyException {

        // make key
        KeyGenerator generator = KeyGenerator.getInstance("HMACSha256");
        Key key = generator.generateKey();
        Utils.printByteArray("hmac key", key.getEncoded());

        // create signature
        Mac mac = Mac.getInstance("HMACSha256");
        mac.init(key);
        byte[] input = "Hello, world!".getBytes();
        byte[] signature = mac.doFinal(input);
        Utils.printByteArray("Signature", signature);

        // validation of signature on the other end
        mac.init(key);
        byte[] newSignature = mac.doFinal(input);
        Utils.printByteArray("Recomputed signature", newSignature);

    }
}
