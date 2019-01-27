package nl.ordina.crypto;

import java.security.GeneralSecurityException;
import java.security.Key;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;

import nl.ordina.crypto.util.Utils;

import org.bouncycastle.util.encoders.Base64;
import org.junit.Test;

public class SymmetricEncryptionECBTest {

	@Test
	public void testSymmetricEncryption() throws GeneralSecurityException {

		// Add BouncyCastle to security providers.
		Utils.loadProvider();

		// make key
		KeyGenerator generator = KeyGenerator.getInstance("AES", "BC");
		// specify we want a key length of 192 bits, allowed for AES
		generator.init(192);
		Key key = generator.generateKey();
		System.out.println("key: " + Utils.byteArrayToHexString(key.getEncoded()));
		System.out.println("key length: " + key.getEncoded().length);

		// make some input
		byte[] input = "hello, JFokus!!!".getBytes();
		System.out.println("input length:" + input.length);

		Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding", "BC");
		System.out.println("input text : " + new String(input) + " bytes:" + input.length);
		// encryption pass

		cipher.init(Cipher.ENCRYPT_MODE, key);
		byte[] encryptedOutput = cipher.doFinal(input);
		System.out.println("cipher text: " + new String(Base64.encode(encryptedOutput)) + " bytes: "
				+ encryptedOutput.length);
		System.out.println("hexadecimal: " + Utils.byteArrayToHexString(encryptedOutput));

		// do encryption pass again
		cipher.init(Cipher.ENCRYPT_MODE, key);
		byte[] encryptedOutput2 = cipher.doFinal(input);
		System.out.println("cipher text: " + new String(Base64.encode(encryptedOutput2)) + " bytes: "
				+ encryptedOutput2.length);
		System.out.println("hexadecimal: " + Utils.byteArrayToHexString(encryptedOutput2));

		// decryption pass

		cipher.init(Cipher.DECRYPT_MODE, key);
		byte[] decryptedOutput = cipher.doFinal(encryptedOutput);
		System.out.println("plain text : " + new String(decryptedOutput) + " bytes: " + decryptedOutput.length);
	}

}
