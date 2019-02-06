package nl.ordina.crypto;

import nl.ordina.crypto.util.Utils;
import org.junit.Test;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.IvParameterSpec;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.SecureRandom;

public class SymmetricEncryptionCBCDemo {

    //2. show key generation
    //3. create string of 128 bytes, explaining block size of AES is 128
    //4. Encrypt, show it's 128 bytes
    //5. Decrypt, show end result
    //6. Notice absence of pattern in CBC

    @Test
    public void testSymmetricEncryption() throws GeneralSecurityException {

        //make key
        KeyGenerator generator = KeyGenerator.getInstance("AES");
        // specify we want a key length of 192 bits, allowed for AES
        generator.init(192);
        Key key = generator.generateKey();
        Utils.printByteArray("key", key.getEncoded());

        //get IV
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        SecureRandom secureRandom = SecureRandom.getInstance("SHA1PRNG");
        byte[] random = new byte[16];
        secureRandom.nextBytes(random);
        IvParameterSpec ivSpec = new IvParameterSpec(random);
        Utils.printByteArray("ivSpec", random);

        //input
        byte[] input = "JFokus!!".repeat(16).getBytes();
        Utils.printText("input", input);

        //encryption
        cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
        byte[] encryptedOutput = cipher.doFinal(input);
        Utils.printByteArray("ciphertext", encryptedOutput);

        //decryption
        cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
        byte[] decryptedOutput = cipher.doFinal(encryptedOutput);
        Utils.printText("decoded input", decryptedOutput);
    }
}
