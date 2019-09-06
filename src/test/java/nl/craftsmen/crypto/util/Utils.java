package nl.craftsmen.crypto.util;

import org.apache.commons.codec.binary.Hex;
import org.apache.ws.security.util.DOM2Writer;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.xml.sax.SAXException;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.StringWriter;
import java.security.Key;
import java.security.Security;

/**
 * Utility class for parsing DOM documents.
 */
public class Utils {

    /**
     * Hide default constructor. Constructs a new DOMUtils.
     */
    private Utils() {
    }

    public static String getDocumentAsString(Node node) {
        StringWriter stringWriter = new StringWriter();
        // omit xml declaration
        DOM2Writer.serializeAsXML(node, stringWriter, true);
        return stringWriter.getBuffer().toString();

    }

    /**
     * Constructs a DOM document from an xml message in string format.
     *
     * @param xml the xml message.
     * @return the xml message as a DOM document.
     */
    public static Document getDocumentFromString(String xml) {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setValidating(false);
        factory.setNamespaceAware(true);
        // Create the builder and parse the xml
        DocumentBuilder builder;
        try {
            builder = factory.newDocumentBuilder();
            return builder.parse(new ByteArrayInputStream(xml.getBytes("UTF-8")));
        } catch (ParserConfigurationException e) {
            throw new RuntimeException(e);
        } catch (SAXException e) {
            throw new RuntimeException(e);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

    }

    public static Document getDocument(String filename) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setValidating(false);
        factory.setNamespaceAware(true);
        // Create the builder and parse the file
        DocumentBuilder builder = factory.newDocumentBuilder();
        Document doc = builder.parse(Utils.class.getResourceAsStream(filename));
        return doc;

    }


    public static void printText(String name, byte[] bytes) {
        System.out.println(name + ": "+ new String(bytes));
        System.out.println(name + "length: " + bytes.length + " bytes, " + bytes.length * 8 + " bits.");
        System.out.println("\r\n");
    }

    public static void printByteArray(String name, byte[] bytes) {
        System.out.println(name + ": "+ Hex.encodeHexString(bytes));
        System.out.println(name + " length: " + bytes.length + " bytes, " + bytes.length * 8 + " bits.");
        System.out.println("\r\n");
    }

    public static String byteArrayToHexString(Key key) {
        return byteArrayToHexString(key.getEncoded());
    }

    public static String byteArrayToHexString(byte[] b) {
        StringBuffer sb = new StringBuffer(b.length * 2);
        for (int i = 0; i < b.length; i++) {
            int v = b[i] & 0xff;
            if (v < 16) {
                sb.append('0');
            }
            sb.append(Integer.toHexString(v));
        }
        return sb.toString().toUpperCase();
    }

    public static void loadProvider() {
        Security.addProvider(new BouncyCastleProvider());
    }

}
