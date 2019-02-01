package nl.ordina.crypto;

import nl.ordina.crypto.util.Utils;
import org.junit.Test;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;

public class ASymmetricEncryptionDemo {

    @Test
    public void encryptSomeShortTextWithRsa() throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IOException, BadPaddingException, IllegalBlockSizeException, NoSuchProviderException {

        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA");
        kpGen.initialize(1024);
        KeyPair keyPair = kpGen.generateKeyPair();
        Utils.printByteArray("private key", keyPair.getPrivate().getEncoded());
        Utils.printByteArray("public key", keyPair.getPublic().getEncoded());


        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPrivate());

        byte[] text = Files.readAllBytes(Path.of("justright.txt"));
        Utils.printText("plain text", text);

        //encrypt
        byte[] encryptedText = cipher.doFinal(text);
        Utils.printByteArray("ciphertext", encryptedText);

        cipher.init(Cipher.DECRYPT_MODE, keyPair.getPublic());
        byte[] plainText = cipher.doFinal(encryptedText);
        Utils.printText("decoded text", plainText);

    }

    @Test
    public void encryptTheFellowshipOfTheRingWithRsa() throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IOException, BadPaddingException, IllegalBlockSizeException, NoSuchProviderException {

        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA");
        kpGen.initialize(1024);
        KeyPair keyPair = kpGen.generateKeyPair();


        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPrivate());

        byte[] text = Files.readAllBytes(Path.of("largefile.txt"));
        byte[] encryptedText = cipher.doFinal(text);
    }


}
