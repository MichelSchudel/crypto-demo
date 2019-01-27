package nl.ordina.crypto;

import nl.ordina.crypto.util.Utils;
import org.bouncycastle.util.encoders.Base64;
import org.junit.Test;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.security.Key;

public class SymmetricEncryptionECBTest {

    //1. show load provider
    //2. show key generation
    //3. create string of 128 bytes, explaining block size of AES is 128
    //4. Encrypt, show it's 128 bytes
    //5. Decrypt, show end result
    //6. Notice pattern in ECB

    @Test
    public void testSymmetricEncryption() throws GeneralSecurityException, UnsupportedEncodingException {

        //1.
        // Add BouncyCastle to security providers.
        Utils.loadProvider();

        // make key
        KeyGenerator generator = KeyGenerator.getInstance("AES");
        // specify we want a key length of 192 bits, allowed for AES
        generator.init(192);
        Key key = generator.generateKey();
        System.out.println("key: " + Utils.byteArrayToHexString(key.getEncoded()));
        System.out.println("key length: " + key.getEncoded().length);

        // make some input
        byte[] input = "JFokus!!".repeat(16).getBytes("UTF-8");
        System.out.println("input length:" + input.length);

        Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
        System.out.println("input text : " + new String(input) + "\r\ninput text length: " + input.length);
        // encryption pass

        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encryptedOutput = cipher.doFinal(input);
        System.out.println("cipher text: " + new String(Base64.encode(encryptedOutput)) + "\r\ncipher text length: "
                + encryptedOutput.length);
        System.out.println("hexadecimal: " + Utils.byteArrayToHexString(encryptedOutput));

        // decryption pass

        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] decryptedOutput = cipher.doFinal(encryptedOutput);
        System.out.println("decoded text : " + new String(decryptedOutput) + "\r\nlength: " + decryptedOutput.length);
    }

}
