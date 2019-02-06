package nl.ordina.crypto;

import nl.ordina.crypto.util.Utils;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import java.security.Key;
import java.security.SecureRandom;

public class WalletEncryptionDemo {

    public static void main(String[] args) throws Exception {
        Utils.loadProvider();
        String password = "password";

        int keyLength = 256;
        int saltLength = keyLength / 8; // It's bytes, not bits.
        int iterations = 65536;
        byte[] salt = new SecureRandom().generateSeed(saltLength);
        PBEKeySpec keySpec = new PBEKeySpec(password.toCharArray(), salt, iterations, keyLength);

        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256", "BC");
        Key passwordKey = secretKeyFactory.generateSecret(keySpec);

        byte[] wallet = "{\"myAccountBalance\": 500}".getBytes();
        Utils.printText("Decrypted wallet: ", wallet);

        Cipher encryptingCipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "BC");
        encryptingCipher.init(Cipher.ENCRYPT_MODE, passwordKey);
        byte[] cipherText = encryptingCipher.doFinal(wallet);
        Utils.printByteArray("Encrypted wallet", cipherText);

        Cipher decryptingCipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "BC");
        byte[] iv = encryptingCipher.getIV();
        decryptingCipher.init(Cipher.DECRYPT_MODE, passwordKey, new IvParameterSpec(iv));
        byte[] plainText = decryptingCipher.doFinal(cipherText);
        Utils.printText("Decrypted wallet: ", plainText);


    }
}
