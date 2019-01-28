package nl.ordina.crypto;

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

public class WalletEncryption2 {

    public static void main(String[] args) throws Exception {
        Security.insertProviderAt(new BouncyCastleProvider(), 1);

        String password = "password";
        String payload = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Aenean in tincidunt metus. Nam nec diam sed velit blandit porta quis et augue. Praesent imperdiet, nulla vel aliquam porta, dui nisi dictum justo, pellentesque elementum purus orci at leo. Duis scelerisque, urna sit amet fringilla interdum, mauris felis sagittis eros, eleifend tincidunt risus nulla ut erat. Aliquam id sapien non neque rutrum lacinia at vitae lorem. Vivamus quis ligula nunc. Aenean facilisis pretium leo, vitae gravida quam ultrices et. Ut venenatis eros in justo semper fermentum. Pellentesque convallis lectus urna, fringilla rhoncus metus faucibus quis. Sed eu rhoncus tortor. Donec lacinia tempor elementum.";

        int keyLength = 256;
        int saltLength = keyLength / 8; // It's bytes, not bits.
        int iterations = 65536;

        byte[] salt = new SecureRandom().generateSeed(saltLength);
        PBEKeySpec keySpec = new PBEKeySpec(password.toCharArray(), salt, iterations, keyLength);
        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256", "BC");
        SecretKey passwordKey = secretKeyFactory.generateSecret(keySpec);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", "BC");
        cipher.init(Cipher.ENCRYPT_MODE, passwordKey);
        byte[] iv = cipher.getIV();
        System.out.println(Arrays.toString(cipher.getIV()));
        byte[] cipherText = cipher.doFinal(payload.getBytes());

        System.out.println(Base64.toBase64String(cipherText));

        keySpec = new PBEKeySpec(password.toCharArray(), salt, iterations, keyLength);
        secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256", "BC");
        passwordKey = secretKeyFactory.generateSecret(keySpec);

        cipher = Cipher.getInstance("AES/GCM/NoPadding", "BC");
        cipher.init(Cipher.DECRYPT_MODE, passwordKey, new IvParameterSpec(iv));
        System.out.println(Arrays.toString(cipher.getIV()));
        byte[] plainText = cipher.doFinal(cipherText);
        System.out.println(new String(plainText));
    }
}
