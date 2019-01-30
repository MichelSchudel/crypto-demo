package nl.ordina.crypto;

import nl.ordina.crypto.util.Utils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Arrays;

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

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "BC");
        cipher.init(Cipher.ENCRYPT_MODE, passwordKey);
        byte[] iv = cipher.getIV();
        System.out.println(Arrays.toString(cipher.getIV()));
        byte[] wallet = "{ \"myAccountBalance\": 500}".getBytes();
        byte[] cipherText = cipher.doFinal(wallet);
        System.out.println("Encrypted wallet: " + Base64.toBase64String(cipherText));

        cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "BC");
        cipher.init(Cipher.DECRYPT_MODE, passwordKey, new IvParameterSpec(iv));
        System.out.println(Arrays.toString(cipher.getIV()));
        byte[] plainText = cipher.doFinal(cipherText);
        System.out.println("Decrypted wallet: " + new String(plainText));
    }
}
