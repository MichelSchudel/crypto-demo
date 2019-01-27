package nl.ordina.crypto;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.io.FileOutputStream;
import java.security.KeyStore;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.Properties;
import java.util.Vector;

import nl.ordina.crypto.util.CryptoToolboxCrypto;
import nl.ordina.crypto.util.SampleKeyStoreFactory;
import nl.ordina.crypto.util.Utils;

import org.apache.ws.security.SOAP11Constants;
import org.apache.ws.security.SOAPConstants;
import org.apache.ws.security.WSEncryptionPart;
import org.apache.ws.security.WSSecurityEngine;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.components.crypto.CryptoFactory;
import org.apache.ws.security.message.WSSecHeader;
import org.apache.ws.security.message.WSSecSignature;
import org.junit.Test;
import org.w3c.dom.Document;

public class SoapSigningTest {

	@Test
	public void testSoapSigning() throws Exception {
		// Add BouncyCastle to security providers.
		Utils.loadProvider();

		// setup key store
		SampleKeyStoreFactory factory = new SampleKeyStoreFactory();
		KeyStore ks = factory.getKeyStore();
		Enumeration<String> aliases = ks.aliases();

		// list key store
		while (aliases.hasMoreElements()) {
			String alias = aliases.nextElement();
			System.out.println("alias: " + alias + ", isKey: " + ks.isKeyEntry(alias));
		}
		FileOutputStream output = new FileOutputStream("c:/temp/keystore.jce");
		ks.store(output, "password".toCharArray());

		// now setup ws security
		Properties cryptoProperties = new Properties();
		cryptoProperties.setProperty("org.apache.ws.security.crypto.provider", CryptoToolboxCrypto.class.getName());
		cryptoProperties.setProperty("org.apache.ws.security.crypto.merlin.keystore.type", "JCEKS");
		cryptoProperties.setProperty("org.apache.ws.security.crypto.merlin.file", "c:/temp/keystore.jce");
		cryptoProperties.setProperty("org.apache.ws.security.crypto.merlin.keystore.password", "password");
		cryptoProperties.setProperty("org.apache.ws.security.crypto.merlin.keystore.alias", "end");
		Document originalDocument = Utils.getDocument("/soap-unsigned.xml");
		System.out.println("original document:" + Utils.getDocumentAsString(originalDocument));
		Document signedDocument = sign(originalDocument, cryptoProperties);
		System.out.println("signed document:" + Utils.getDocumentAsString(signedDocument));
		assertTrue(verify(signedDocument, cryptoProperties));

		// now, tamper with the data and see if the signature fails.
		String signedXml = Utils.getDocumentAsString(signedDocument);
		// tamper with the subject info.
		String tamperedXml = signedXml.replaceAll("CN=Test", "CN =wddwTest ");
		Document tamperedDoc = Utils.getDocumentFromString(tamperedXml);
		System.out.println("tampered document:" + Utils.getDocumentAsString(tamperedDoc));
		assertFalse(verify(tamperedDoc, cryptoProperties));

	}

	/**
	 * {@inheritDoc}
	 */
	public Document sign(Document aMessage, Properties cryptoProperties) {


		try {
			SOAPConstants soapConstants = new SOAP11Constants();

			WSSecSignature signature = new WSSecSignature();
			signature.setUserInfo("privateKey", "");
			WSSecHeader header = new WSSecHeader();

			Crypto crypto = CryptoFactory.getInstance(cryptoProperties);
			header.insertSecurityHeader(aMessage);

			// this is optional since the body is signed by default
			List<WSEncryptionPart> parts = new ArrayList<WSEncryptionPart>();
			WSEncryptionPart part = new WSEncryptionPart(soapConstants.getBodyQName().getLocalPart(),
					soapConstants.getEnvelopeURI(), "Content");
			parts.add(part);
			signature.setParts(new Vector<WSEncryptionPart>(parts));
			// END optional part
			return signature.build(aMessage, crypto, header);
		} catch (WSSecurityException e) {
			throw new RuntimeException(e);
		}
	}

	/**
	 * {@inheritDoc}
	 */
	public boolean verify(Document aSignedMessage, Properties cryptoProperties) {
		try {
			cryptoProperties.setProperty("org.apache.ws.security.crypto.merlin.keystore.alias", "end");
			Crypto crypto = CryptoFactory.getInstance(cryptoProperties);
			WSSecurityEngine secEngine = new WSSecurityEngine();
			// CallbackHandler cb = new T();
			secEngine.processSecurityHeader(aSignedMessage, null, null, crypto);
			return true;
		} catch (WSSecurityException e) {
			return false;
		}

	}
}
