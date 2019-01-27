package nl.ordina.crypto;

import static org.junit.Assert.assertEquals;

import java.security.GeneralSecurityException;
import java.security.Key;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;

import nl.ordina.crypto.util.Utils;

import org.junit.Test;

public class SymmetricSigningTest {

	@Test
	public void testSymmetricSigning() throws GeneralSecurityException {
		// Add BouncyCastle to security providers.
		Utils.loadProvider();

		// make key
		KeyGenerator generator = KeyGenerator.getInstance("HMACSha256", "BC");
		Key key = generator.generateKey();
		System.out.println("key: " + Utils.byteArrayToHexString(key.getEncoded()));
		System.out.println("key length: " + key.getEncoded().length);

		// create signature
		Mac mac = Mac.getInstance("HMACSha256");
		mac.init(key);
		byte[] input = "Hello, world!".getBytes();
		byte[] signature = mac.doFinal(input);
		System.out.println("Signature:" + Utils.byteArrayToHexString(signature));

		// validation of signature
		byte[] recievedInput = "Hello, world! ".getBytes();
		byte[] newSignature = mac.doFinal(recievedInput);
		System.out.println("New signature:" + Utils.byteArrayToHexString(newSignature));

		// now compare newly generated signature with received signature
		assertEquals(new String(signature), new String(newSignature));

	}
}
