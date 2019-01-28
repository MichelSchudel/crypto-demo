package nl.ordina.crypto;

import nl.ordina.crypto.util.Utils;
import org.junit.Test;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;

public class WalletEncryption {


    @Test
    public void testSymmetricEncryption() throws GeneralSecurityException, UnsupportedEncodingException {
        Utils.loadProvider();

        Key key = getKeyFromPassword("password");

        // make some input
        byte[] input = "JFokus!!".repeat(16).getBytes("UTF-8");
        System.out.println("input text : " + new String(input) + "\r\ninput text length: " + input.length);
        System.out.println("input length:" + input.length);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", "BC");
        // encryption pass

        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encryptedOutput = cipher.doFinal(input);
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] decryptedOutput = cipher.doFinal(encryptedOutput);
        System.out.println("decoded text : " + new String(decryptedOutput) + "\r\nlength: " + decryptedOutput.length);

    }

    private Key getKeyFromPassword(String password) throws NoSuchAlgorithmException, InvalidKeySpecException {
        char[] pw = password.toCharArray();
        byte[] salt = new SecureRandom().generateSeed(256 /8 );
        PBEKeySpec spec = new PBEKeySpec(pw,salt,65536,256);
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        SecretKey secretKey = keyFactory.generateSecret(spec);
        return secretKey;
    }
}
