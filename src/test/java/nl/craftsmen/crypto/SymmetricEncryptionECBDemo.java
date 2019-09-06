package nl.craftsmen.crypto;

import nl.craftsmen.crypto.util.Utils;
import org.junit.Test;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import java.security.GeneralSecurityException;
import java.security.Key;

public class SymmetricEncryptionECBDemo {

    //2. show key generation
    //3. create string of 128 bytes, explaining block size of AES is 128
    //4. Encrypt, show it's 128 bytes
    //5. Decrypt, show end result
    //6. Notice pattern in ECB

    @Test
    public void testSymmetricEncryption() throws GeneralSecurityException {


        KeyGenerator generator = KeyGenerator.getInstance("AES");
        // specify we want a key length of 192 bits, allowed for AES
        generator.init(192);
        Key key = generator.generateKey();
        Utils.printByteArray("key", key.getEncoded());

        byte[] input = "JavaZone".repeat(16).getBytes();
        Utils.printText("input", input);

        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encryptedOutput = cipher.doFinal(input);
        Utils.printByteArray("ciphertext", encryptedOutput);

        //decryption on the other end
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] decryptedOutput = cipher.doFinal(encryptedOutput);
        Utils.printText("decoded input", decryptedOutput);


    }

}
