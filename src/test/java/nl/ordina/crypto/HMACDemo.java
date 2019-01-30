package nl.ordina.crypto;

import nl.ordina.crypto.util.Utils;
import org.junit.Test;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

import static org.junit.Assert.assertEquals;

public class HMACDemo {

    @Test
    public void testHMac() throws NoSuchAlgorithmException, InvalidKeyException {

        // make key
        KeyGenerator generator = KeyGenerator.getInstance("HMACSha256");
        Key key = generator.generateKey();
        System.out.println("key: " + Utils.byteArrayToHexString(key.getEncoded()));
        System.out.println("key length: " + key.getEncoded().length);

        // create signature
        Mac mac = Mac.getInstance("HMACSha256");
        mac.init(key);
        byte[] input = "Hello, world!".getBytes();
        byte[] signature = mac.doFinal(input);
        System.out.println("Signature:" + Utils.byteArrayToHexString(signature));

        // validation of signature
        mac.init(key);
        byte[] newSignature = mac.doFinal(input);
        System.out.println("New signature:" + Utils.byteArrayToHexString(newSignature));

        // now compare newly generated signature with received signature
        assertEquals(new String(signature), new String(newSignature));

    }
}
