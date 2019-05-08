package nl.craftsmen.crypto;

import nl.craftsmen.crypto.util.Utils;

import org.junit.Test;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * A small message digest demo.
 */
public class HashingDemo {

	private void hashText(String s) throws NoSuchAlgorithmException {
		MessageDigest digester = MessageDigest.getInstance("SHA-256");
		byte[] input = s.getBytes();
		byte[] digest = digester.digest(input);
		System.out.println("Input: " + s);
		Utils.printByteArray("Digest", digest);
	}

	@Test
	public void hashingDemo() throws NoSuchAlgorithmException {

		// get a message digest
		System.out.println("one way only!");
		hashText("The quick brown fox jumped over the lazy dog.");

		//hash it again, deterministic
		System.out.println("deterministic");
		hashText("The quick brown fox jumped over the lazy dog.");

		// psuedorandom, new digest looks nothing like old digest
		System.out.println("psuedorandom");
		hashText("The quick brown fox jumped ower the lazy dog.");

		// hash is always fixed length.
		System.out.println("fixedlength");
		hashText("The quick brown fox jumped ower the lazy dog and a lot more stuff happened after that.");



	}


}
