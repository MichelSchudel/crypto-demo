package nl.ordina.crypto;

import nl.ordina.crypto.util.Utils;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import java.security.SecureRandom;

public class WalletEncryptionDemo {

    public static void main(String[] args) throws Exception {
        Utils.loadProvider();

        //generate a secret key from a password
        String password = "password";
        int keyLength = 256;
        int saltLength = keyLength / 8; // It's bytes, not bits.
        int iterations = 65536;
        byte[] salt = new SecureRandom().generateSeed(saltLength);
        PBEKeySpec keySpec = new PBEKeySpec(password.toCharArray(), salt, iterations, keyLength);

        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256", "BC");
        SecretKey passwordKey = secretKeyFactory.generateSecret(keySpec);

        byte[] wallet = "{ \"myAccountBalance\": 500}".getBytes();
        Utils.printText("Decrypted wallet: ",  wallet);

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "BC");
        cipher.init(Cipher.ENCRYPT_MODE, passwordKey);
        byte[] iv = cipher.getIV();
        Utils.printByteArray("IV",  iv);

        byte[] cipherText = cipher.doFinal(wallet);
        Utils.printByteArray("Encrypted wallet",  cipherText);

        cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "BC");
        cipher.init(Cipher.DECRYPT_MODE, passwordKey, new IvParameterSpec(iv));
        Utils.printByteArray("IV",  iv);

        byte[] plainText = cipher.doFinal(cipherText);
        Utils.printText("Decrypted wallet: ",  plainText);
    }
}
