package nl.craftsmen.crypto;

import nl.craftsmen.crypto.util.Utils;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;

public class WalletEncryptionDemo {

    public static void main(String[] args) throws Exception {
        Utils.loadProvider();

        Key passwordKey = getPasswordKey("myPassword");


        byte[] wallet = "{\"myAccountBalance\": 500}".getBytes();
        Utils.printText("Decrypted wallet: ", wallet);

        Cipher encryptingCipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "BC");
        encryptingCipher.init(Cipher.ENCRYPT_MODE, passwordKey);
        byte[] cipherText = encryptingCipher.doFinal(wallet);
        Utils.printByteArray("Encrypted wallet", cipherText);

        Cipher decryptingCipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "BC");
        byte[] iv = encryptingCipher.getIV();

        decryptingCipher.init(Cipher.DECRYPT_MODE, passwordKey, new IvParameterSpec(iv));
        byte[] plainText2 = decryptingCipher.doFinal(cipherText);
        Utils.printText("Decrypted wallet: ", plainText2);


    }

    private static Key getPasswordKey(String password) throws InvalidKeySpecException, NoSuchProviderException, NoSuchAlgorithmException {
        int keyLength = 256;
        int saltLength = keyLength / 8; // It's bytes, not bits.
        int iterations = 65536;
        byte[] salt = new SecureRandom().generateSeed(saltLength);
        PBEKeySpec passwordKeySpec = new PBEKeySpec(password.toCharArray(), salt, iterations, keyLength);
        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256", "BC");
        Key passwordKey = secretKeyFactory.generateSecret(passwordKeySpec);
        return passwordKey;
    }
}
