package nl.ordina.crypto;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;

import nl.ordina.crypto.util.Utils;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Test;

/**
 * A small message digest demo.
 */
public class MessageDigestDemo {

	//1. show hash
	//2. change one letter
	//3. Make the message longer
	//4. Change provider

	@Test
	public void testCryptoDemo() throws NoSuchAlgorithmException {
		// Add BouncyCastle to security providers.
		Security.addProvider(new BouncyCastleProvider());

		//MessageDigest digester = MessageDigest.getInstance("SHA-256");
		MessageDigest digester = MessageDigest.getInstance("SHA-256");

		// get a message digest
		hashText("The quick brown fox jumped over the lazy dog.", digester);

		//hash it again, deterministic
		hashText("The quick brown fox jumped over the lazy dog.", digester);

		// psuedorandom, new digest looks nothing like old digest
		hashText("The quick brown fox jumped ower the lazy dog.", digester);

		// hash is always fixed length.
		hashText("The quick brown fox jumped ower the lazy dog and a lot more stuff happened after that.", digester);

	}

	private void hashText(String s, MessageDigest digester) throws NoSuchAlgorithmException {
		byte[] input = s.getBytes();
		byte[] digest = digester.digest(input);
		System.out.println(Utils.byteArrayToHexString(digest));
		System.out.println("length of digest:" + digest.length);
	}
}
