package nl.ordina.crypto.util;

import java.io.IOException;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.math.BigInteger;
import java.security.KeyStoreException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.Properties;

import javax.security.auth.x500.X500Principal;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.components.crypto.CredentialException;
import org.apache.ws.security.components.crypto.Merlin;

/**
 * Extension of Merlin class to fix bug WS-218 of WSS4J where the alias lookup based on a serial and issuer fails if
 * there are other objects in the keystore besides certificates. TODO remove this class and replace it with Merlin in
 * the SOAPSignerImpl when WSS4J 1.5.9 is released, which fixes this bug.
 */
public class CryptoToolboxCrypto extends Merlin {

    /** Logger. */
    private static final Logger LOG = LogManager.getLogger(CryptoToolboxCrypto.class);

    /** Constant. */
    private static final Constructor<Object> BC_509CLASS_CONS;

    /**
     * Load the x509name
     */
    static {
        Constructor cons = null;
        Class c;
        try {
            c = Class.forName("org.bouncycastle.asn1.x509.X509Name");
            cons = c.getConstructor(new Class[] {String.class});
        } catch (ClassNotFoundException e) {
            LOG.error(e);
        } catch (SecurityException e) {
            LOG.error(e);
        } catch (NoSuchMethodException e) {
            LOG.error(e);
        }
        BC_509CLASS_CONS = cons;
    }

    /**
     * Constructs a new CryptoToolboxCrypto.
     * @param properties the properties.
     * @throws CredentialException if an error occurs.
     * @throws IOException if an error occurs.
     */
    public CryptoToolboxCrypto(Properties properties) throws CredentialException, IOException {
        super(properties);
    }

    /**
     * Constructs a new CryptoToolboxCrypto.
     * @param properties the properties.
     * @param loader the loader.
     * @throws CredentialException if an error occurs.
     * @throws IOException if an error occurs.
     */
    public CryptoToolboxCrypto(Properties properties, ClassLoader loader) throws CredentialException, IOException {
        super(properties, loader);
    }

    /**
     * Create the x509 name.
     * @param s the name.
     * @return an x500principal.
     */
    protected Object createBCX509Name(String s) {
        if (BC_509CLASS_CONS != null) {
            try {
                return BC_509CLASS_CONS.newInstance(new Object[] {s});
            } catch (IllegalArgumentException e) {
                LOG.error(e);
            } catch (InstantiationException e) {
                LOG.error(e);
            } catch (IllegalAccessException e) {
                LOG.error(e);
            } catch (InvocationTargetException e) {
                LOG.error(e);
            }
        }
        return new X500Principal(s);
    }

    /**
     * {@inheritDoc}
     */
    public final String getAliasForX509Cert(String issuer, BigInteger serialNumber) throws WSSecurityException {
        return getAliasForX509Cert(issuer, serialNumber, true);
    }

    /**
     * Get the alias.
     * @param issuer the issuer.
     * @param serialNumber the serial number.
     * @param useSerialNumber indicates if the serial number should be used in the lookup.
     * @return the alias if found, or null.
     * @throws WSSecurityException if an error occurs.
     */
    protected final String getAliasForX509Cert(String issuer, BigInteger serialNumber, boolean useSerialNumber)
            throws WSSecurityException {
        Object issuerName = null;
        Certificate cert = null;

        //
        // Convert the issuer DN to a java X500Principal object first. This is to ensure
        // interop with a DN constructed from .NET, where e.g. it uses "S" instead of "ST".
        // Then convert it to a BouncyCastle X509Name, which will order the attributes of
        // the DN in a particular way (see WSS-168). If the conversion to an X500Principal
        // object fails (e.g. if the DN contains "E" instead of "EMAILADDRESS"), then fall
        // back on a direct conversion to a BC X509Name
        //
        try {
            X500Principal issuerRDN = new X500Principal(issuer);
            issuerName = createBCX509Name(issuerRDN.getName());
        } catch (java.lang.IllegalArgumentException ex) {
            issuerName = createBCX509Name(issuer);
        }

        try {
            for (Enumeration<String> e = keystore.aliases(); e.hasMoreElements();) {
                String alias = (String) e.nextElement();
                // BEGIN fix
                if (keystore.isCertificateEntry(alias)) {
                    // END fix
                    Certificate[] certs = keystore.getCertificateChain(alias);

                    if (certs == null || certs.length == 0) {
                        // no cert chain, so lets check if getCertificate gives us a result.
                        cert = keystore.getCertificate(alias);
                        if (cert == null) {
                            return null;
                        }
                    } else {
                        cert = certs[0];
                    }
                    if (cert instanceof X509Certificate) {
                        X509Certificate x509cert = (X509Certificate) cert;
                        if (!useSerialNumber || x509cert.getSerialNumber().compareTo(serialNumber) == 0) {
                            Object certName = createBCX509Name(x509cert.getIssuerDN().getName());
                            if (certName.equals(issuerName)) {
                                return alias;
                            }
                        }
                    }
                    // BEGIN fix
                }
                // END fix
            }
        } catch (KeyStoreException e) {
            throw new WSSecurityException(WSSecurityException.FAILURE, "keystore", null, e);
        }
        return null;
    }

}
