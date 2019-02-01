package nl.ordina.crypto;

import nl.ordina.crypto.util.Utils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Test;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Security;

/**
 * A small message digest demo.
 */
public class HashingDemo {

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
		System.out.println("one way only!");
		hashText("The quick brown fox jumped over the lazy dog.", digester);

		//hash it again, deterministic
		System.out.println("deterministic");
		hashText("The quick brown fox jumped over the lazy dog.", digester);

		// hash is always fixed length.
		System.out.println("fixedlength");
		hashText("The quick brown fox jumped ower the lazy dog and a lot more stuff happened after that.", digester);

		// psuedorandom, new digest looks nothing like old digest
		System.out.println("psuedorandom");
		hashText("The quick brown fox jumped ower the lazy dog.", digester);


	}

	private void hashText(String s, MessageDigest digester) {
		byte[] input = s.getBytes();
		byte[] digest = digester.digest(input);
		System.out.println("Input: " + s);
		System.out.println("Digest: " + Utils.byteArrayToHexString(digest));
		System.out.println("length of digest:" + digest.length);
		System.out.println("\r\n");
	}
}
